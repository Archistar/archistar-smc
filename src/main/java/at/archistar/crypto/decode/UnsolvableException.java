package at.archistar.crypto.decode;

/**
 * Exception that is thrown if a decoder cannot decode it's input
 */
public class UnsolvableException extends Exception {

    private final String errorMsg;
    
    UnsolvableException(String msg) {
        this.errorMsg = msg;
    }
    
    UnsolvableException() {
        this.errorMsg = "generic error";
    }
}
