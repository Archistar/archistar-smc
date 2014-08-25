package at.archistar.crypto.secretsharing;

import at.archistar.crypto.data.Share;
import at.archistar.crypto.exceptions.ReconstructionException;
import at.archistar.crypto.exceptions.WeakSecurityException;

/**
 * <p>This is the abstract base class for all Secret-Sharing algorithms.</p>
 * 
 * <p><i>Secret Sharing</i> means splitting up some secret (for example a message) in <i>n</i> pieces such that any number of
 * at least <i>k</i> pieces can reconstruct the secret, but <i>k - 1</i> pieces yield absolutely no information about the
 * secret.</p>
 * 
 * For detailed information, see: 
 * <a href="http://en.wikipedia.org/wiki/Secret_sharing">http://en.wikipedia.org/wiki/Secret_sharing</a>
 * 
 * @author Elias Frantar
 * @version 2014-7-22
 */
public abstract class SecretSharing {
    protected final int n; // number of shares
    protected final int k; // minimum number of valid shares required for reconstruction
    
    /**
     * Constructor (can and should only be called from sub-classes)
     * 
     * @param n the number of shares to create
     * @param k the minimum number of valid shares required for reconstruction
     * @throws WeakSecurityException if the scheme is not secure for the given parameters
     */
    protected SecretSharing(int n, int k) throws WeakSecurityException {
        checkSecurity(n, k); // validate security
        
        this.n = n;
        this.k = k;
    }
    
    /* abstract methods which need to have different implementations for every Secret-Sharing scheme */
    
    /**
     * Creates <i>n</i> secret shares for the given data where <i>k</i> shares are required for reconstruction. 
     * (n, k should have been previously initialized)
     * @param data the data to share secretly
     * @return the n different secret shares for the given data
     */
    public abstract Share[] share(byte[] data);
    /**
     * Attempts to reconstruct the secret from the given shares.<br>
     * This will fail if there are fewer than k (previously initialized) valid shares.
     * 
     * @param shares the shares to reconstruct the secret from
     * @return the reconstructed secret
     * @throws ReconstructionException thrown if the reconstruction failed
     */
    public abstract byte[] reconstruct(Share[] shares) throws ReconstructionException;
    
    /* class methods for parameter validation */
    
    /**
     * Checks if this Secret-Sharing scheme is secure enough for the given parameters.<br>
     * (throws a WeakSecurityException if this is the case)
     * 
     * @param n the number of shares to create
     * @param k the minimum number of valid shares required for reconstruction
     * @throws WeakSecurityException thrown if the Secret-Sharing scheme is not secure enough
     */
    protected static void checkSecurity(int n, int k) throws WeakSecurityException { // n is there in case we want to override this
        if (k < 2) {
            throw new WeakSecurityException();
        }
    }
    /**
     * Checks if there are enough shares for reconstruction.<br>
     * <i>(This method assumes all shares to be valid!)</i>
     * 
     * @param n the number of shares to reconstruct from
     * @param k the minimum number of valid shares required for reconstruction
     * @return true if there are enough shares; false otherwise
     */
    protected static boolean validateShareCount(int n, int k) {
        return n >= k; // base implementation; necessary condition for every Secret-Sharing scheme
    }
    
    /* only Getters; objects of this class should be immutable */
    public int getN() { return n; }
    public int getK() { return k; }
}
