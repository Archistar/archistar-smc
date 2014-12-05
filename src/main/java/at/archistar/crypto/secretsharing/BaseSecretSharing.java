package at.archistar.crypto.secretsharing;

/**
 * <p>This is the abstract base class for all Secret-Sharing algorithms.</p>
 * 
 * <p><i>Secret Sharing</i> means splitting up some secret (for example a message) in <i>n</i> pieces such that any number of
 * at least <i>k</i> pieces can reconstruct the secret, but <i>k - 1</i> pieces yield absolutely no information about the
 * secret.</p>
 * 
 * For detailed information, see: 
 * <a href="http://en.wikipedia.org/wiki/Secret_sharing">http://en.wikipedia.org/wiki/Secret_sharing</a>
 */
abstract class BaseSecretSharing implements SecretSharing {
    
    /** number of shares */
    protected final int n;
    
    /** minimum number of valid shares required for reconstruction */
    protected final int k;
    
    /**
     * Constructor (can and should only be called from sub-classes)
     * 
     * @param n the number of shares to create
     * @param k the minimum number of valid shares required for reconstruction
     * @throws WeakSecurityException if the scheme is not secure for the given parameters
     */
    protected BaseSecretSharing(int n, int k) throws WeakSecurityException {
        checkSecurity(n, k); // validate security
        
        this.n = n;
        this.k = k;
    }
    
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
    
    @Override
    public int getN() {
        return n;
    }
    
    @Override
    public int getK() {
        return k;
    }
}
