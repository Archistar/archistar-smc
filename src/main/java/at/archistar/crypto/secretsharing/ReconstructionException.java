package at.archistar.crypto.secretsharing;

/**
 * Exception that is thrown when the reconstruction of a secret failed.
 */
public class ReconstructionException extends Exception {
    private static final long serialVersionUID = 1L;
    
    private final String msg;

    ReconstructionException() {
        this.msg = "generic";
    }
    
    ReconstructionException(String msg) {
        this.msg = msg;
    }
}
