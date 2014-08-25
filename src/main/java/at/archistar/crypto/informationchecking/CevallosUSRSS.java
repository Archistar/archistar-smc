package at.archistar.crypto.informationchecking;

import at.archistar.crypto.secretsharing.SecretSharing;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.data.VSSShare;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.random.RandomSource;
import at.archistar.crypto.mac.MacHelper;
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
 * 
 * @author Elias Frantar
 * @version 2014-7-29
 */
public class CevallosUSRSS extends RabinBenOrRSS {
    public static final int E = 128; // security constant for computing the tag length; means 128 bit
    
    private final SecretSharing sharing;
    private final MacHelper mac;
    
    /**
     * Constructor.
     */
    public CevallosUSRSS(SecretSharing sharing, MacHelper mac, RandomSource rng) throws WeakSecurityException {
        super(sharing, mac, rng);
        
        if (!((sharing.getK() - 1) * 3 >= sharing.getN() && (sharing.getK() - 1) * 2 < sharing.getN())) {
            throw new WeakSecurityException("this scheme only works when n/3 <= t < n/2 (where t = k-1)");
        }
        
        this.sharing = sharing;
        this.mac = mac;
    }
    
    @Override
    protected Share[] checkShares(VSSShare[] cshares) {
        
        Queue<Integer> queue = new LinkedList<Integer>();
        List<Share> valid = new LinkedList<Share>();

        // accepts[i][j] = true means participant j accepts i
        boolean[][] accepts = new boolean[n + 1][n + 1];
        int a[] = new int[n + 1];
        
        for (VSSShare s1 : cshares) {
            for (VSSShare s2 : cshares) {
                accepts[s1.getId()][s2.getId()] = mac.verifyMAC(
                            s1.getShare().serialize(), s1.getMacs().get((byte) s2.getId()),
                            s2.getMacKeys().get((byte) s1.getId()));
                a[s1.getId()] += accepts[s1.getId()][s2.getId()] ? 1 : 0;
            }
            if (a[s1.getId()] < k) {
                queue.add(s1.getId());
            } else {
                valid.add(s1.getShare());
            }
        }
        
        while (valid.size() >= k && !queue.isEmpty()) {
            int s1id = queue.poll();
            for (Iterator<Share> it = valid.iterator(); it.hasNext();) {
                Share s2 = it.next();
                if (accepts[s2.getId()][s1id]) {
                    a[s2.getId()]--;
                    if (a[s2.getId()] < k) {
                        queue.add(s2.getId());
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
     * @param m the length of the message in bit
     * @param k the number of shares required for reconstruction
     * @param e the security constant in bit
     * @return the amount of bytes the MAC-tags should have
     */
    public static int computeTagLength(int m, int k, int e) {
        return (log2(k) + log2(m) + 2 / k * e + log2(e)) / 8; // result in bytes
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
        return "CevallosUSRSS(" + sharing + ", " + mac + ")";
    }
}
