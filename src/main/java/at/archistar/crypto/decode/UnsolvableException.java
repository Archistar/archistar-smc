package at.archistar.crypto.decode;

/**
 * Exception that is thrown if a decoder cannot decode it's input
 */
public class UnsolvableException extends Exception {

    UnsolvableException(String msg) {
        super(msg);
    }

    UnsolvableException() {
        super("generic error");
    }
}
