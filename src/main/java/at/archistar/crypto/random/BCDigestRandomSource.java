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
    
    public BCDigestRandomSource() {
        this.digest = new SHA1Digest();
        this.drng = new DigestRandomGenerator(digest);
    }
    
    public BCDigestRandomSource(Digest digest) {
        this.digest = digest;
        this.drng = new DigestRandomGenerator(digest);
    }

    @Override
    public void fillBytes(byte[] toBeFilled) {
        this.drng.nextBytes(toBeFilled);
    }

    @Override
    public void fillBytesAsInts(int[] toBeFilled) {
        byte[] result = new byte[toBeFilled.length];
        fillBytes(result);
        
        for (int i = 0; i < toBeFilled.length; i++) {
            toBeFilled[i] = result[i] % 256;
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
