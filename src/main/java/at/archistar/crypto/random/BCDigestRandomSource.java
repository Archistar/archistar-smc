package at.archistar.crypto.random;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.prng.DigestRandomGenerator;

/**
 *
 * @author andy
 */
public class BCDigestRandomSource implements RandomSource {
    
    private final DigestRandomGenerator drng;
    
    private final Digest digest;
    
    /**
     * create a new RandomSource using default params (SHA1-based)
     */
    public BCDigestRandomSource() {
        this.digest = new SHA1Digest();
        this.drng = new DigestRandomGenerator(digest);
    }

    /**
     * create a new RandomSource using the passed digest
     * @param digest the algorithm to base the RandomSource on
     */
    public BCDigestRandomSource(Digest digest) {
        this.digest = digest;
        this.drng = new DigestRandomGenerator(digest);
    }

    /**
     * fill an (byte) array with random data
     * @param toBeFilled the array to be filled
     */
    @Override
    public void fillBytes(byte[] toBeFilled) {
        this.drng.nextBytes(toBeFilled);
    }

    /**
     * fill an (byte) array with random data
     * @param toBeFilled the array to be filled
     */
    @Override
    public void fillBytesAsInts(int[] toBeFilled) {
        byte[] result = new byte[toBeFilled.length];
        fillBytes(result);
        
        for (int i = 0; i < toBeFilled.length; i++) {
            toBeFilled[i] = (result[i] < 0) ? result[i] + 256 : result[i];
        }
    }
    
    /**
     * @return human readable representation of this random source
     */
    @Override
    public String toString() {
        return "BCDigestRandomSource(" + digest.getAlgorithmName() + ")";
    }
}
