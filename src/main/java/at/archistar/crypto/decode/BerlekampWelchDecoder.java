package at.archistar.crypto.decode;

import java.util.Arrays;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import at.archistar.crypto.math.GF;
import at.archistar.crypto.math.GFMatrix;
import at.archistar.crypto.math.GFFactory;
import at.archistar.crypto.math.GenericPolyHelper;

/**
 * Reconstructs a polynomial from the given xy-pairs using the 
 * <a href="http://en.wikipedia.org/wiki/Berlekamp–Welch_algorithm">Berlekamp-Welch algorithm</a>.<br>
 * This algorithm tolerates up to <i>(n - k) / 2</i> errors (wrong points) when reconstructing the polynomial.
 */
public class BerlekampWelchDecoder implements Decoder {
    private final int[][] matrix;
    private final int[] x;
    private final int f; // max number of allowed errors
    private final int k; // (degree+1), number of reconstructed elements
    
    private final GFFactory gffactory;
    private final GF gf;
    
    /**
     * Constructor
     */
    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public BerlekampWelchDecoder(final int[] xValues,
                                 final int k,
                                 final GFFactory gffactory) {
        
        final int n = xValues.length;
        this.gffactory = gffactory;
        this.gf = gffactory.createHelper();
        this.k = k;
        this.f = (n - k) / 2;
        this.x = xValues;
        
        /* prepare the Q(x) part of the matrix */
        this.matrix = new int[n][n];
        
        /* how many should be correct? */
        final int t = x.length - f;
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < t; j++) {
                matrix[i][j] = gf.pow(x[i], j);
            }
        }
    }
    /**
     * Prepares the <i>E(x)</i> part of the matrix (the not constant part). Must be done for every solve.
     * @param y the y-coordinates to use for preparation
     */
    private void prepareEx(int[] y) {
        final int t = y.length - f;

        for (int i = 0; i < y.length; i++) {
            for (int j = t; j < y.length; j++) {
                matrix[i][j] = gf.mult(y[i], gf.pow(x[i], j-t));
            }
        }
    }
   
    @Override
    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public int[] decode(int[] y, int errors) throws UnsolvableException {
        if (x.length != y.length) {
            throw new UnsolvableException("Number of x-values does not equal number of y-values!");
        }
        
        if (errors > this.f) {
            throw new UnsolvableException("too many errors for this decoder (f=" + this.f + ", errors=" + errors + ")");
        }
        
        int[] ret = new int[k];
        
        return decodeUnsafe(ret, y, errors);
    }
    
    private static int getDegree(int[] coefficients) {
        final int d = coefficients.length - 1;
        
        if (coefficients.length == 0 || coefficients[d] == 0) {
            return -1;
        } else {
            return d;
        }
    }
    
    /**
     * Constructs the vector which will be multiplied with the decode-matrix.
     * 
     * @param x the x-values
     * @param y the corresponding y-values
     * @param length the length of the resulting vector (in case some rows have been eliminated)
     * @return the vector which then can be multiplied with the result-matrix to compute the coefficients
     */
    private int[] buildMultVector(final int x[], final int y[], final int length) {
        final int[] res = new int[length];
        
        for (int i = 0; i < length; i++) {
            res[i] = gf.mult(gf.pow(x[i], f), y[i]);
        }
        
        return res;
    }

    @Override
    public int[] decodeUnsafe(final int[] ret, final int[] y, final int errors) throws UnsolvableException {
                
        /* finish preparation of the decode-matrix */
        prepareEx(y);
        
        GFMatrix decodeMatrix = gffactory.createMatrix(matrix).inverseElimDepRows();
        int[] coeffs = decodeMatrix.rightMultiply(buildMultVector(x, y, decodeMatrix.getNumRows())); // compute the coefficients
        
        coeffs = Arrays.copyOf(coeffs, y.length + 1); // fill 0s for eliminated rows
        coeffs[coeffs.length - 1] = 1; // add 1 to coeffs since E(x) = e_0 + e_1*x + ... + x^f
        
        /* construct Q(x) and E(x) */
        int[] q = Arrays.copyOfRange(coeffs, 0, coeffs.length - (f + 1));
        int[] e = Arrays.copyOfRange(coeffs, coeffs.length - (f + 1), coeffs.length);
        
        GenericPolyHelper div = new GenericPolyHelper(gf);
        int[][] divRes = div.polyDiv(q, e);
        
        if (getDegree(divRes[1]) > 0) { // if there is a remainder, reconstruction failed
            throw new UnsolvableException();
        }
        
        for (int i = 0; i < k; i++) {
            if (i < divRes[0].length) {
                ret[i] = divRes[0][i];
            } else {
                ret[i] = 0;
            }
        }
        
        return ret;
    }
}
