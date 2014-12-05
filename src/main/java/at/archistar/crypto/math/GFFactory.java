package at.archistar.crypto.math;

/**
 * Factory for creating GF
 */
public interface GFFactory {
    
    /**
     * @return the newly created GF
     */
    public GF createHelper();
    
    /**
     * @param matrix integer representation of a matrix
     * @return a newly created GFMatrix
     */
    public GFMatrix createMatrix(int matrix[][]);
}
