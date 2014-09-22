package at.archistar.crypto.decode;

import java.util.Arrays;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import at.archistar.crypto.exceptions.ImpossibleException;
import at.archistar.crypto.math.CustomMatrix;
import at.archistar.crypto.math.GF256;
import org.bouncycastle.pqc.math.linearalgebra.GF2mField;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialGF2mSmallM;

/**
 * Reconstructs a polynomial from the given xy-pairs using the 
 * <a href="http://en.wikipedia.org/wiki/Berlekamp–Welch_algorithm">Berlekamp-Welch algorithm</a>.<br>
 * This algorithm tolerates up to <i>(n - k) / 2</i> errors (wrong points) when reconstructing the polynomial.
 * 
 * @author Andreas Happe
 * @author Elias Frantar
 * @version 2014-7-25
 */
public class BerlekampWelchDecoder implements Decoder {
    private final int[][] matrix;
    private final int[] x;
    private final int f; // max number of allowed errors
    private final int k; // (degree+1), number of reconstructed elements
    
    /**
     * Constructor
     */
    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public BerlekampWelchDecoder(int[] xValues, int k) {
        
        int n = xValues.length;
        
        this.k = k;
        this.f = (n - k) / 2;
        this.x = xValues;
        
        /* prepare the Q(x) part of the matrix */
        matrix = new int[n][n];
        
        /* how many should be correct? */
        int t = x.length - f;
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < t; j++) {
                matrix[i][j] = GF256.pow(x[i], j);
            }
        }
    }
    /**
     * Prepares the <i>E(x)</i> part of the matrix (the not constant part). Must be done for every solve.
     * @param y the y-coordinates to use for preparation
     */
    private void prepareEx(int[] y) {
        int t = y.length - f;

        for (int i = 0; i < y.length; i++) {
            for (int j = t; j < y.length; j++) {
                matrix[i][j] = GF256.mult(y[i], GF256.pow(x[i], j-t));
            }
        }
    }
   
    @Override
    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public int[] decode(int[] y, int errors) throws UnsolvableException {
        if (x.length != y.length) {
            throw new ImpossibleException("Number of x-values does not equal number of y-values!");
        }
        
        if (errors > this.f) {
            throw new UnsolvableException("too many errors for this decoder (f=" + this.f + ", errors=" + errors + ")");
        }
        
        /* finish preparation of the decode-matrix */
        prepareEx(y);
        CustomMatrix decodeMatrix = new CustomMatrix(matrix).computeInverseElimDepRows();
        
        int[] coeffs = decodeMatrix.rightMultiply(buildMultVector(x, y, decodeMatrix.getNumRows())); // compute the coefficients
        int[] ret = new int[k];
        
        coeffs = Arrays.copyOf(coeffs, y.length + 1); // fill 0s for eliminated rows
        coeffs[coeffs.length - 1] = 1; // add 1 to coeffs since E(x) = e_0 + e_1*x + ... + x^f
        
        /* construct Q(x) and E(x) */
        PolynomialGF2mSmallM q = new PolynomialGF2mSmallM(new GF2mField(8, 0x11d), Arrays.copyOfRange(coeffs, 0, coeffs.length - (f + 1)));
        PolynomialGF2mSmallM e = new PolynomialGF2mSmallM(new GF2mField(8, 0x11d), Arrays.copyOfRange(coeffs, coeffs.length - (f + 1), coeffs.length));
        
        /* calculate P(X) = Q(x) / E(x) */
        PolynomialGF2mSmallM[] divRes = q.div(e);
        
        if (divRes[1].getDegree() > 0) { // if there is a remainder, reconstruction failed
            throw new UnsolvableException();
        }
        
        for (int i = 0; i < k; i++) { // flexiprovider does not support getCoeffs() ...
            ret[i] = divRes[0].getCoefficient(i);
        }
        
        return ret;
    }
    
    /**
     * Constructs the vector which will be multiplied with the decode-matrix.
     * 
     * @param x the x-values
     * @param y the corresponding y-values
     * @param length the length of the resulting vector (in case some rows have been eliminated)
     * @return the vector which then can be multiplied with the result-matrix to compute the coefficients
     */
    private int[] buildMultVector(int x[], int y[], int length) {
        int[] res = new int[length];
        
        for (int i = 0; i < length; i++) {
            res[i] = GF256.mult(GF256.pow(x[i], f), y[i]);
        }
        
        return res;
    }
}
