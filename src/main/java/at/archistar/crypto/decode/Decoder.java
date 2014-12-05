package at.archistar.crypto.decode;

/**
 * Reconstruct/Decode a polynomial from n given points.
 */
public interface Decoder {
    
    /**
     * Reconstructs all coefficients of the polynomial defined by the given points.<br>
     * 
     * @param y the corresponding y-coordinates to the x-coordinates given when calling {@link #prepare(int[])}
     * @param errors error count
     * @return an array of all coefficients of this polynomial
     * @throws UnsolvableException if the polynomial was not solvable
     */
    int[] decode(int[] y, int errors) throws UnsolvableException;
    
    /**
     * Reconstructs all coefficients of the polynomial defined by the given points.
     * This version performs no input validation and does not allocate memory.
     * 
     * @param y the corresponding y-coordinates to the x-coordinates given when calling {@link #prepare(int[])}
     * @param errors error count
     * @return an array of all coefficients of this polynomial
     * @throws UnsolvableException if the polynomial was not solvable
     */
    int[] decodeUnsafe(int[] target, int[] y, int errors) throws UnsolvableException;
}
