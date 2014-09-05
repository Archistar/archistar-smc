package at.archistar.crypto.data;

/**
 * This is thrown if a Constructor parameter violates security constraints (or
 * just doesn't make any sense
 */
public class InvalidParametersException extends Exception {
    private final String errorMsg;
    
    InvalidParametersException(String msg) {
        this.errorMsg = msg;
    }
    
    InvalidParametersException() {
        this.errorMsg = "generic error";
    }
}
