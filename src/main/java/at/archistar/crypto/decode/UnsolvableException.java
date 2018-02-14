package at.archistar.crypto.decode;

/**
 * Exception that is thrown if a decoder cannot decode its input
 */
public class UnsolvableException extends Exception {

    UnsolvableException(String msg) {
        super(msg);
    }
}
