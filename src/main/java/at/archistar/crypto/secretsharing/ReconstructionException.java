package at.archistar.crypto.secretsharing;

/**
 * Exception that is thrown when the reconstruction of a secret failed.
 */
public class ReconstructionException extends Exception {

    /**
     * creates a reconstruction exception with an error message
     *
     * @param msg the to be used error message
     */
    public ReconstructionException(String msg) {
        super(msg);
    }
}
