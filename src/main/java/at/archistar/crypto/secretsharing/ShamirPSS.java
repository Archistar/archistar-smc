package at.archistar.crypto.secretsharing;

import at.archistar.crypto.data.InvalidParametersException;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.data.ShareFactory;
import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.math.GF;
import at.archistar.crypto.math.OutputEncoderConverter;
import at.archistar.crypto.random.RandomSource;
import java.util.HashMap;
import java.util.Map;

/**
 * <p>This class implements the Perfect-Secret-Sharing-scheme (PSS) developed by Adi Shamir.</p>
 * 
 * <p>This implementation utilizes GeometricSecretSharing to obtain most of this
 * algorithm's implementation -- it's main addition is the encoding/decoding of
 * secrets into the equations coefficients ([a_0 .. a_k] in GeometricSecretSharing's
 * documentation). Shamir just sets one coefficient (a_0 in our implementation)
 * to the secret and sets all other coefficients to random data. Compared to other
 * schemes this yields security but has the payoff of being rather slow.</p>
 * 
 * <p>For a detailed description of the scheme, 
 * see: <a href='http://en.wikipedia.org/wiki/Shamir's_Secret_Sharing'>http://en.wikipedia.org/wiki/Shamir's_Secret_Sharing</a></p>
 */
public class ShamirPSS extends GeometricSecretSharing {
    
    private final RandomSource rng;
    
    /**
     * Constructor
     * 
     * @param n the number of shares to create
     * @param k the minimum number of shares required for reconstruction
     * @param rng the source of randomness to use for generating the coefficients
     * @param decoderFactory the solving algorithm to use for reconstructing the secret
     * @throws WeakSecurityException thrown if this scheme is not secure enough for the given parameters
     */
    public ShamirPSS(int n, int k, RandomSource rng, DecoderFactory decoderFactory, GF gf) throws WeakSecurityException {
        super(n, k, decoderFactory, gf);
        
        this.dataPerRound = 1;
        this.rng = rng;
    }
    
    @Override
    public String toString() {
        return "ShamirPSS(" + n + "/" + k + ")";
    }

    @Override
    protected void encodeData(int[] coeffs, byte[] data, int offset, int length) {
        this.rng.fillBytesAsInts(coeffs);
        coeffs[0] = (data[offset] < 0) ? data[offset] + 256 : data[offset];
    }

    @Override
    protected int decodeData(int[] encoded, int originalLength, byte[] result, int offset) {
        result[offset++] = (byte)encoded[0];
        return offset;
    }

    @Override
    protected Share[] createShares(int[] xValues, OutputEncoderConverter[] results, int originalLength) throws InvalidParametersException {
        Share shares[] = new Share[n];
        Map<Byte, byte[]> metadata = new HashMap<>();
        
        for (int i = 0; i < n; i++) {
            shares[i] = ShareFactory.create(Share.ShareType.SHAMIR_PSS, (byte)xValues[i], results[i].getEncodedData(), metadata);
        }

        return shares;
    }

    @Override
    protected int retrieveInputLength(Share[] shares) {
        return shares[0].getYValues().length;
    }
}
