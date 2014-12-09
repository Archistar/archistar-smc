package at.archistar.crypto.secretsharing;

import at.archistar.crypto.data.InvalidParametersException;
import at.archistar.crypto.data.Share;
import static at.archistar.crypto.data.Share.ORIGINAL_LENGTH;
import at.archistar.crypto.data.ShareFactory;
import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.math.GF;
import at.archistar.crypto.math.OutputEncoderConverter;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

/**
 * <p>This class implements Rabin IDS (aka Reed-Solomon Code).</p>
 * 
 * <p>Note: this scheme does not provide security but is rather used for quickly
 * distributing data that is not sensitive (or encrypted through other means).</p>
 * 
 * <p>This implementation utilizes GeometricSecretSharing to obtain most of this
 * algorithm's implementation -- it's main addition is the encoding/decoding of
 * secrets into the equations coefficients ([a_0 .. a_k] in GeometricSecretSharing's
 * documentation). Rabin evenly distributes the original data between shares --
 * thus a0..a_k is just filled in with the original data.</p>
 * 
 * <p>For a detailed description of this scheme, see: 
 * <a href='http://en.wikipedia.org/wiki/Reed–Solomon_error_correction'>http://en.wikipedia.org/wiki/Reed–Solomon_error_correction</a></p>
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
        
        /* TODO: replace with array copy */
        
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
        
        Share shares[] = new Share[n];
        Map<Byte, byte[]> metadata = new HashMap<>();
        metadata.put(ORIGINAL_LENGTH, ByteBuffer.allocate(4).putInt(originalLength).array());
        
        for (int i = 0; i < n; i++) {
            shares[i] = ShareFactory.create(Share.ShareType.RABIN_IDS, (byte)xValues[i], results[i].getEncodedData(), metadata);
        }

        return shares;
    }

    @Override
    protected int retrieveInputLength(Share[] shares) {
        return shares[0].getMetadata(ORIGINAL_LENGTH);
    }
}
