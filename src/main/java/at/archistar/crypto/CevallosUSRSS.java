package at.archistar.crypto;

import at.archistar.crypto.data.Share;
import at.archistar.crypto.data.VSSShare;
import at.archistar.crypto.decode.BerlekampWelchDecoderFactory;
import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.exceptions.ImpossibleException;
import at.archistar.crypto.exceptions.ReconstructionException;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.random.RandomSource;
import at.archistar.crypto.random.SHA1PRNG;
import at.archistar.helper.ShareHelper;
import at.archistar.helper.ShareMacHelper;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

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
public class CevallosUSRSS extends SecretSharing {
    private static final String MAC = "HMacSHA512";
    private static final int E = 128; // security constant for computing the tag length; means 128 bit
    
    private int keyTagLength;
    
    private final SecretSharing sharing;
    private ShareMacHelper mac; // final has been omitted to allow a try/catch-block in constructor
    
    /**
     * Constructor.
     * 
     * @param n the number of shares to create
     * @param k the minimum number of (correct) shares required to reconstruct the message (degree of the polynomial + 1)
     *          must be in range: <i>n/3 <= k-1 < n/2</i> ({@link ImpossibleException} if thrown if that constraint is violated)
     * @param rng the source of randomness to be used
     * @param decoderFactory the decoder to be used
     * @throws WeakSecurityException thrown if this scheme is not secure for the given parameters
     */
    public CevallosUSRSS(int n, int k, DecoderFactory decoderFactory, RandomSource rng) throws WeakSecurityException {
        super(n, k);
        
        if (!((k - 1) * 3 >= n && (k - 1) * 2 < n)) {
            throw new WeakSecurityException("this scheme only works when n/3 <= t < n/2 (where t = k-1)");
        }
        
        /* this scheme requires ShamirPSS */
        sharing = new ShamirPSS(n, k, rng, decoderFactory);
        
        try {
            // we are using HMacSHA256 at the moment
            mac = new ShareMacHelper(MAC, new SHA1PRNG());
        } catch (NoSuchAlgorithmException e) {
            throw new ImpossibleException("algorithm unknown?");
        }
    }
    
    @Override
    public Share[] share(byte[] data) {
        keyTagLength = computeTagLength(data.length * 8, k, E); // keyLength equals tagLength
                
        VSSShare[] cshares = ShareHelper.createVSSShares(sharing.share(data), keyTagLength, keyTagLength);
        
        /* compute and add the corresponding tags */
        for (VSSShare share1 : cshares) {
            for (VSSShare share2 : cshares) {
                try {
                    byte[] key = mac.genSampleKey(keyTagLength);
                    byte[] tag = mac.computeMAC(share1.getShare(), key, keyTagLength);
                    
                    share1.getMacs().put((byte) share2.getId(), tag);
                    share2.getMacKeys().put((byte) share1.getId(), key);
                } catch (InvalidKeyException e) {
                     throw new ImpossibleException("TODO: find a good exception message");
                }
            }
        }
        
        return cshares;
    }

    @Override
    public byte[] reconstruct(Share[] shares) throws ReconstructionException {
        VSSShare[] cshares = safeCast(shares); // we need access to its inner fields
        
        /* create an accepts table */
        boolean[][] accepts = new boolean[n + 1][n + 1]; // accepts[i][j] means participant j accepts i
        int a[] = new int[n + 1];

        for (VSSShare s1 : cshares){
            for (VSSShare s2 : cshares){
                accepts[s1.getId()][s2.getId()] = mac.verifyMAC(s1.getShare(), s1.getMacs().get((byte) s2.getId()), s2.getMacKeys().get((byte) s1.getId())); 
                a[s1.getId()] += accepts[s1.getId()][s2.getId()] ? 1 : 0;
            }
        }
            
        
        /* build a group I such that only shares with at least k accepts are in there */
        List<Share> valid = new LinkedList<Share>(Arrays.asList(ShareHelper.extractUnderlyingShares(cshares)));
            
        boolean bad;
        while (valid.size() >= k) {
            bad = false;
            Iterator<Share> i1 = valid.iterator();
            while (!bad && i1.hasNext()) {
                Share s1 = i1.next();
                if (a[s1.getId()] < k) { // share is not accepted by enough others
                    i1.remove();   
                    for (Share s2: valid){
                        a[s2.getId()] -= accepts[s2.getId()][s1.getId()] ? 1 : 0;
                    }
                    bad = true;
                }
            }
            if (!bad){
                break;
            }
        }
        
        if (valid.size() >= k) {
            return sharing.reconstruct(valid.toArray(new Share[valid.size()]));
        }
        
        throw new ReconstructionException(); // if there weren't enough valid shares
    }
    
    /**
     * Converts the Share[] to a VSSShrare[] by casting each element individually.
     * 
     * @param shares the shares to cast
     * @return the given Share[] as VSSShrare[]
     * @throws ClassCastException if the Share[] did not (only) contain VSSShrares
     */
    private VSSShare[] safeCast(Share[] shares) {
        VSSShare[] rboshares = new VSSShare[shares.length];
        
        for (int i = 0; i < shares.length; i++) {
            rboshares[i] = (VSSShare) shares[i];
        }
        
        return rboshares;
    }
    
    /* helper functions */
    
    /**
     * Computes the required MAC-tag-length to achieve a security of <i>e</i> bits.
     * 
     * @param m the length of the message in bit
     * @param k the number of shares required for reconstruction
     * @param e the security constant in bit
     * @return the amount of bytes the MAC-tags should have
     */
    private int computeTagLength(int m, int k, int e) {
        return (log2(k) + log2(m) + 2 / k * e + log2(e)) / 8; // result in bytes
    }
    
    /**
     * Computes the integer logarithm base 2 of a given number.
     * 
     * @param n the int to compute the logarithm for
     * @return the integer logarithm (whole number -> floor()) of the given number
     */
    private int log2(int n){
        if (n <= 0) {
            throw new IllegalArgumentException();
        }
        
        return 31 - Integer.numberOfLeadingZeros(n);
    }
}
