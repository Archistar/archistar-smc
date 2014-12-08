package at.archistar.crypto.secretsharing;

/**
 * This exception is thrown when the given parameters for sharing a secret are
 * not secure enough.
 */
public class WeakSecurityException extends Exception {
    private static final long serialVersionUID = 1L;
    
    private final String msg;

    WeakSecurityException() {
        this.msg = "none given";
    }
    
    /**
     * create a new exceeption that denotes that an algorithm was configured
     * in such a way, that it would yield no security or privacy
     * 
     * @param msg an detailed error message
     */
    public WeakSecurityException(String msg) {
        this.msg = msg;
    }
}
