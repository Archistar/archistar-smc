package at.archistar.crypto.decode;

import at.archistar.crypto.exceptions.ImpossibleException;

/**
 * The base interface for all different schemes for reconstructing a polynomial from n given points.
 * 
 * @author Elias Frantar
 * @version 2014-7-25
 */
public abstract class PolySolver {
    boolean prepared = false;
    
    /**
     * Prepares the solve by doing computations in advance which can be reused for reconstructing multiple polynomials.
     * @param x the x-values of the polynomial's points
     */
    public abstract void prepare(int[] x);
    
    /**
     * Reconstructs all coefficients of the polynomial defined by the given points.<br>
     * (The solve must have been prepared before! Otherwise an {@link ImpossibleException} will be thrown.)
     * 
     * @param y the corresponding y-coordinates to the x-coordinates given when calling {@link #prepare(int[])}
     * @return an array of all coefficients of this polynomial; null if the polynomial was not solvable
     */
    public abstract int[] solve(int[] y);
}
