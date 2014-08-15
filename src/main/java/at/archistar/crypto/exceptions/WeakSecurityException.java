package at.archistar.crypto.exceptions;

/**
 * This exception is thrown when the given parameters for sharing a secret are
 * not secure enough.
 *
 * @author Fehrenbach Franca-Sofia
 * @version 2014-7-21
 */
public class WeakSecurityException extends Exception {
    private static final long serialVersionUID = 1L;
    
    private final String msg;

    public WeakSecurityException() {
        this.msg = "none given";
    }
    
    public WeakSecurityException(String msg) {
        this.msg = msg;
    }
}
