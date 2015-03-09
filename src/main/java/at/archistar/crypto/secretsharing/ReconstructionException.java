package at.archistar.crypto.secretsharing;

/**
 * Exception that is thrown when the reconstruction of a secret failed.
 */
public class ReconstructionException extends Exception {
    private static final long serialVersionUID = 1L;
    
    private final String msg;

    /**
     * creates a generic reconstruction exception
     */
    public ReconstructionException() {
        this.msg = "generic";
    }
    
    /**
     * creates a reconstuction exception with an error message
     * @param msg  the to be used error message
     */
    public ReconstructionException(String msg) {
        this.msg = msg;
    }
}
