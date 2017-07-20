package at.archistar.crypto.data;

/**
 * This is thrown if a Constructor parameter violates security constraints (or
 * just doesn't make any sense
 */
public class InvalidParametersException extends Exception {

    public InvalidParametersException(String msg) {
        super(msg);
    }

    InvalidParametersException() {
        super("generic");
    }
}
