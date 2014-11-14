/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package at.archistar.crypto.secretsharing;

import at.archistar.crypto.data.BaseShare;
import at.archistar.crypto.data.InvalidParametersException;
import at.archistar.crypto.data.ShamirShare;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.decode.Decoder;
import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.decode.ErasureDecoderFactory;
import at.archistar.crypto.decode.UnsolvableException;
import at.archistar.crypto.exceptions.ReconstructionException;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.math.EncodingConverter;
import at.archistar.crypto.math.GF;
import at.archistar.crypto.math.gf257.GF257;
import at.archistar.crypto.math.gf257.GF257Factory;
import at.archistar.crypto.math.ntt.AbstractNTT;
import at.archistar.crypto.math.ntt.NTTSlow;
import at.archistar.crypto.random.FakeRandomSource;
import at.archistar.crypto.random.RandomSource;
import static at.archistar.crypto.secretsharing.SecretSharing.validateShareCount;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author andy
 */
public class NTTEncoder extends SecretSharing {

    private final RandomSource rng;

    private final GF gf;

    private final int blockLength = 256;

    private final AbstractNTT ntt;
    
    private final DecoderFactory decoderFactory = new ErasureDecoderFactory(new GF257Factory());

    NTTEncoder() throws WeakSecurityException {
        super(7, 3);
        
        this.gf = new GF257();
        this.rng = new FakeRandomSource();
        this.ntt = new NTTSlow(this.gf);
    }

    @Override
    public Share[] share(byte[] data) {

        int dataLength = blockLength / n;
        int xValues[] = new int[n];
        
        xValues[0] = 1;
        for (int i = 1; i < n; i++) {
            xValues[i] = gf.mult(xValues[i-1], 256);
        }

        EncodingConverter output[] = new EncodingConverter[n];
        for (int i = 0; i < n; i++) {
            output[i] = new EncodingConverter(data.length, gf);
        }

        for (int i = 0; i < data.length / dataLength; i++) {
            int[] tmp = new int[blockLength]; // initialized with 0

            System.arraycopy(data, dataLength * i, tmp, 0, dataLength);

            int[] random = new int[dataLength * (k - 1)];
            rng.fillBytesAsInts(random);

            System.arraycopy(random, 0, tmp, dataLength, random.length);

            int[] conv = ntt.ntt(tmp, 256);
            for (int j = 0; j < n; j++) {
                for (int x = 0; x < dataLength; x++) {
                    output[n].append(conv[j * dataLength + x]);
                }
            }
        }

        ShamirShare shares[] = new ShamirShare[n];
        for (int j = 0; j < n; j++) {
            try {
                shares[j] = new ShamirShare((byte) xValues[j], output[j].getEncodedData());
            } catch (InvalidParametersException ex) {
                Logger.getLogger(NTTEncoder.class.getName()).log(Level.SEVERE, null, ex);
                assert(false);
            }
        }
        return shares;
        // TODO: do rest
    }

    @Override
    public byte[] reconstruct(Share[] shares) throws ReconstructionException {
        if (!validateShareCount(shares.length, k)) {
            throw new ReconstructionException();
        }

        /* you cannot cast arrays to arrays of subtype in java7 */
        ShamirShare[] sshares = Arrays.copyOf(shares, shares.length, ShamirShare[].class); // we need access to the inner fields
        
        EncodingConverter input[] = new EncodingConverter[shares.length];
        for (int i = 0; i < shares.length; i++) {
            input[i] = new EncodingConverter(sshares[i].getY(), gf);
        }

        byte[] result = new byte[sshares[0].getY().length];
        int[] xVals = BaseShare.extractXVals(sshares);
        
        Decoder decoder = decoderFactory.createDecoder(xVals, k);
        for (int i = 0; i < result.length; i++) { // reconstruct all individual parts of the secret
            int[] yVals = new int[input.length];
            for (int j = 0; j < input.length; j++) {
                yVals[j] = input[j].readNext();
            }
            
            try {
                result[i] = (byte) decoder.decode(yVals, 0)[0];
            } catch (UnsolvableException e) {
                throw new ReconstructionException("too few shares to reconstruct");
            }
        }   
        
        return result;

    }
}