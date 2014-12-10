package at.archistar.crypto.informationchecking;

import at.archistar.crypto.data.Share;
import at.archistar.crypto.secretsharing.WeakSecurityException;
import at.archistar.crypto.mac.MacHelper;
import at.archistar.crypto.random.RandomSource;
import java.io.IOException;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;

/**
 * <p>This class implements the <i>Unconditionally-Secure Robust Secret Sharing with Compact Shares</i>-scheme developed by:
 * Alfonso Cevallos, Serge Fehr, Rafail Ostrovsky, and Yuval Rabani.</p>
 * 
 * <p>This system basically equals the RabinBenOrRSS, but has shorter tags and therefore requires a different, 
 * more secure reconstruction phase.</p>
 * 
 * <p>For detailed information about this system, see: 
 * <a href="http://www.iacr.org/cryptodb/data/paper.php?pubkey=24281">http://www.iacr.org/cryptodb/data/paper.php?pubkey=24281</a></p>
 */
public class CevallosUSRSS extends RabinBenOrRSS {
    
    /**
     * security constant for computing the tag length; means 128 bit
     */
    public static final int E = 128;
    
    private final MacHelper mac;
    
    private final int n;
    
    /**
     * Constructor.
     */
    public CevallosUSRSS(int n, int k, MacHelper mac, RandomSource rng) throws WeakSecurityException {
        super(k, mac, rng);
        
        this.n = n;
        
        if (!((k - 1) * 3 >= n) && ((k - 1) * 2 < n)) {
            throw new WeakSecurityException("this scheme only works when n/3 <= t < n/2 (where t = k-1)");
        }
        
        this.mac = mac;
    }
    
    private int getAcceptedCount(Share s1, Share[] shares, boolean[][] accepts) {
        
        int counter = 0;
        
        for (Share s2 : shares) {
            try {
                byte[] data = s1.getSerializedForHashing();
                byte[] mac1 = s1.getMacs().get((byte) s2.getId());
                byte[] mac2 = s2.getMacKeys().get((byte) s1.getId());

                accepts[s1.getId()][s2.getId()] = mac.verifyMAC(data, mac1, mac2);
                if (accepts[s1.getId()][s2.getId()]) {
                    counter++;
                }
            } catch (IOException ex) {
                throw new RuntimeException("this should never happen!");
            }
        }
        
        return counter;
    }
    
    @Override
    public Share[] checkShares(Share[] cshares) {
        
        Queue<Integer> queue = new LinkedList<>();
        List<Share> valid = new LinkedList<>();
        
        // accepts[i][j] = true means participant j accepts i
        boolean[][] accepts = new boolean[n + 1][n + 1];
        int a[] = new int[n + 1];
        
        for (Share s1 : cshares) {
            
            a[s1.getId()] += getAcceptedCount(s1, cshares, accepts);
            
            if (a[s1.getId()] < k) {
                queue.add((int)s1.getId());
            } else {
                valid.add(s1);
            }
        }
        
        while (valid.size() >= k && !queue.isEmpty()) {
            int s1id = queue.poll();
            for (Iterator<Share> it = valid.iterator(); it.hasNext();) {
                Share s2 = it.next();
                if (accepts[s2.getId()][s1id]) {
                    a[s2.getId()]--;
                    if (a[s2.getId()] < k) {
                        queue.add((int)s2.getId());
                        it.remove();
                    }
                }
            }
        }
        
        return valid.toArray(new Share[valid.size()]);
    }
    
    /**
     * Computes the required MAC-tag-length to achieve a security of <i>e</i> bits.
     * 
     * @param m the length of the message in bit (TODO: this should be the blocklength)
     * @param t amount of "defective" shares
     * @param e the security constant in bit
     * @return the amount of bytes the MAC-tags should have
     */
    public static int computeTagLength(int m, int t, int e) {
        int tagLengthBit = log2(t+1) + log2(m) + 2 / (t+1) * e + log2(e);
        return tagLengthBit/8;
    }
    
    /**
     * Computes the integer logarithm base 2 of a given number.
     * 
     * @param n the int to compute the logarithm for
     * @return the integer logarithm (whole number -> floor()) of the given number
     */
    private static int log2(int n){
        if (n <= 0) {
            throw new IllegalArgumentException();
        }
        
        return 31 - Integer.numberOfLeadingZeros(n);
    }
    
    @Override
    public String toString() {
        return "Cevallos(" + k + "/" + n +", " + mac + ")";
    }
}
