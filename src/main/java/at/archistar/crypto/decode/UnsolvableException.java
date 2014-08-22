package at.archistar.crypto.decode;

/**
 *
 * @author andy
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
