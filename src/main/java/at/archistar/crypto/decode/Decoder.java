package at.archistar.crypto.decode;

import at.archistar.crypto.exceptions.ImpossibleException;

/**
 * Reconstruct/Decode a polynomial from n given points.
 * 
 * @author Andreas Happe
 * @author Elias Frantar
 */
public interface Decoder {
    
    /**
     * Reconstructs all coefficients of the polynomial defined by the given points.<br>
     * (The solve must have been prepared before! Otherwise an {@link ImpossibleException} will be thrown.)
     * 
     * @param y the corresponding y-coordinates to the x-coordinates given when calling {@link #prepare(int[])}
     * @return an array of all coefficients of this polynomial
     * @throws UnsolvableException if the polynomial was not solvable
     */
    int[] decode(int[] y) throws UnsolvableException;
}
