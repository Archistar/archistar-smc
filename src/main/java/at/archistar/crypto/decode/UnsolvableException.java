package at.archistar.crypto.decode;

/**
 *
 * @author andy
 */
public class UnsolvableException extends Exception {

    private final String errorMsg;
    
    UnsolvableException(String erasuredecoder_cannot_fix_errors) {
        this.errorMsg = erasuredecoder_cannot_fix_errors;
    }
    
    UnsolvableException() {
        this.errorMsg = "generic error";
    }
}
