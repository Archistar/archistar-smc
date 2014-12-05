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
    
    public WeakSecurityException(String msg) {
        this.msg = msg;
    }
}
