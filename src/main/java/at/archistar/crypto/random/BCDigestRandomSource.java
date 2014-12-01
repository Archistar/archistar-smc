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
    
    public BCDigestRandomSource() {
        this.drng = new DigestRandomGenerator(new SHA1Digest());
    }
    
    public BCDigestRandomSource(Digest digest) {
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
    
}
