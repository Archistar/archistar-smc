package at.archistar.crypto.math;

/**
 * Matrix operations within GF
 */
public interface GFMatrix {
    
    /**
     * right-multiply the matrix with a vector
     *
     * @param vec the vector to be used
     * @return the multiplication's result
     */
    public int[] rightMultiply(int vec[]);
    
    /**
     * create an inverse matrix while automatically reducing dependent
     * rows
     * 
     * @return the inverted matrix
     */
    public GFMatrix inverseElimDepRows();

    /**
     * create the inverse matrix.
     * 
     * @return the inverse matrix
     */
    public GFMatrix inverse();
    
    /**
     * @return the matrix's row count
     */
    public int getNumRows();
    
    /**
     * optimized version of rightMultiply. This version does not
     * allocate memory on it's own.
     * 
     * @param result where to store the result
     * @param vec the vector that is on the right side of the multiplication
     * @return the result (same as result parameter)
     */
    public int[] rightMultiplyInto(int[] result, int[] vec);
}
