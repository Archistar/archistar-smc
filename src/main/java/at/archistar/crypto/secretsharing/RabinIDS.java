package at.archistar.crypto.secretsharing;

import at.archistar.crypto.data.InvalidParametersException;
import at.archistar.crypto.data.ReedSolomonShare;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.math.EncodingConverter;
import at.archistar.crypto.math.GF;
import at.archistar.crypto.math.OutputEncoderConverter;
import java.util.Arrays;

/**
 * <p>This class implements the <i>Rabin IDS</i> (also called <i>Reed Solomon Code</i>) scheme.</p>
 * 
 * <p>For a detailed description of this scheme, see: 
 * <a href='http://en.wikipedia.org/wiki/Reed–Solomon_error_correction'>http://en.wikipedia.org/wiki/Reed–Solomon_error_correction</a></p>
 *  
 * <p><b>NOTE:</b> This scheme is not secure at all. It should only be used for sharing already encrypted 
 *                 data like for example how it is done in {@link KrawczykCSS}.</p>
 */
public class RabinIDS extends GeometricSecretSharing {
    
    /**
     * Constructor
     * 
     * @param n the number of shares to create
     * @param k the minimum number of shares required for reconstruction
     * @param decoderFactory the solving algorithm to use for reconstructing the secret
     * @param gf the field within which we will be doing all our computation
     * @throws WeakSecurityException thrown if this scheme is not secure enough for the given parameters
     */
    public RabinIDS(int n, int k, DecoderFactory decoderFactory, GF gf) throws WeakSecurityException {
        super(n, k, decoderFactory, gf);
        
        this.dataPerRound = k;
    }

    @Override
    public String toString() {
        return "RabinIDS(" + n + "/" + k + ")";
    }
    
    @Override
    protected void encodeData(int coeffs[], byte[] data, int offset, int length) {
        for (int j = 0; j < k; j++) {
            // let k coefficients be the secret in this polynomial
            // todo: optimize, use array copy
            if ((offset+j) < data.length) {
                coeffs[j] = (data[offset+j] < 0) ? data[offset+j] + 256 : data[offset+j];
            } else {
                coeffs[j] = 0;
            }
        }
    }

    @Override
    protected int decodeData(int[] encoded, int originalLength, byte[] result, int offset) {
        for (int j = encoded.length - 1; j >= 0 && offset < originalLength; j--) {
            result[offset++] = (byte)encoded[encoded.length - 1 - j];
        }
        return offset;
    }

    @Override
    protected Share[] createShares(int[] xValues, OutputEncoderConverter[] results, int originalLength) throws InvalidParametersException {
        ReedSolomonShare shares[] = new ReedSolomonShare[n];
        
        for (int i = 0; i < n; i++) {
            shares[i] = new ReedSolomonShare((byte)xValues[i], results[i].getEncodedData(), originalLength);
        }

        return shares;
    }

    @Override
    protected EncodingConverter[] prepareInput(Share[] shares) {
        ReedSolomonShare[] rsshares = Arrays.copyOf(shares, shares.length, ReedSolomonShare[].class);
            
        EncodingConverter input[] = new EncodingConverter[shares.length];
        for (int i = 0; i < shares.length; i++) {
            input[i] = new EncodingConverter(rsshares[i].getY(), gf);
        }
        return input;
    }

    @Override
    protected int retrieveInputLength(Share[] shares) {
        return ((ReedSolomonShare)shares[0]).getOriginalLength();
    }
}
