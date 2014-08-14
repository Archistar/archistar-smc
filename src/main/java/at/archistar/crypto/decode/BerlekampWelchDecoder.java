package at.archistar.crypto.decode;

import java.util.Arrays;

import de.flexiprovider.common.math.codingtheory.GF2mField;
import de.flexiprovider.common.math.codingtheory.PolynomialGF2mSmallM;
import at.archistar.crypto.exceptions.ImpossibleException;
import at.archistar.crypto.math.CustomMatrix;
import at.archistar.crypto.math.GF256;

/**
 * Reconstructs a polynomial from the given xy-pairs using the 
 * <a href="http://en.wikipedia.org/wiki/Berlekamp–Welch_algorithm">Berlekamp-Welch algorithm</a>.<br>
 * This algorithm tolerates up to <i>(n - k) / 2</i> errors (wrong points) when reconstructing the polynomial.
 * 
 * @author Elias Frantar
 * @version 2014-7-25
 */
public class BerlekampWelchDecoder extends PolySolver {
    private int[][] matrix;
    private int[] x;
    
    private int f; // max number of allowed errors
    private int k; // number of points required for reconstruction
    
    /**
     * Constructor
     * @param order the order of the polynomial to reconstruct
     */
    public BerlekampWelchDecoder(int order) {
        this.k = order + 1;
    }

    /**
     * Prepares the <i>Q(x)</i> part of the matrix (the constant part). Must be only done once.
     * @param x the x-coordinates to use for preparation
     */
    private void prepareQx(int[] x) {
        matrix = new int[x.length][x.length];
        
        int t = x.length - f;
        for (int i = 0; i < x.length; i++) {
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
    public void prepare(int[] x) {
        /* compute the number of max allowed errors */
        f = (x.length - k) / 2; // (n - k) / 2
        
        this.x = x;
        prepareQx(x);
        // this.matrix = new GF256Matrix(matrix).computeInverseElimDepRows(); // compute inverse and eliminate all dependent rows
        prepared = true;
    }
    
    @Override
    public int[] solve(int[] y) {
        /* catch some common errors */
        if (!prepared) {
            throw new ImpossibleException("Solve has not been prepared properly!");
        }

        if (x.length != y.length) {
            throw new ImpossibleException("Number of x-values does not equal number of y-values!");
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
            return null;
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
