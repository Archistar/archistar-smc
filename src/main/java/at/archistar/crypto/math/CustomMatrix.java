package at.archistar.crypto.math;

import de.flexiprovider.common.math.codingtheory.GF2mField;
import de.flexiprovider.common.math.linearalgebra.GF2mMatrix;

/**
 * <p>A matrix operating in GF(256).</p>
 * 
 * <p>Uses {@link GF256} for optimized operations and provides some additional methods in contrary to the flexiprovider-
 * class.</p>
 *
 * @author Elias Frantar <i>(added documentation)</i>
 * @author Andreas Happe <andreashappe@snikt.net>
 * @version 2014-7-18
 */
public class CustomMatrix extends GF2mMatrix {
	private static final GF2mField gf256 = new GF2mField(8, 0x11d); // Galois-Field (x^8 + x^4 + x^3 + x + 1 = 0) / 285
	
	/**
     * Constructor
     * @param data the data to put into the matrix
     */
    public CustomMatrix(int[][] data) {
        super(gf256, data);
    }

    /**
	 * Constructor
	 * @param encoded the encoded matrix (got via {@link #getEncoded()})
	 */
    public CustomMatrix(byte[] encoded) {
        super(gf256, encoded);
    }

    /**
     * Performs a matrix * vector multiplication.
     * 
     * <b>NOTE:</b> Matrix multiplication is not commutative. (A*B != B*A) and so does only work if A(MxN) and B(NxO).
     * 		 		Throws an {@link ArithmeticException} if this condition is violated.
     * 
     * @param vec the vector to multiply the matrix with (a 1D-matrix)
     * @return the product of the matrix and the given vector <i>(matrix * vector)</i>
     */
    public int[] rightMultiply(int vec[]) {
    	if (vec.length != matrix.length || vec.length != matrix[0].length) { // multiplication only works if A(MxN) and B(NxO)
    		throw new ArithmeticException("when matrix is MxN, vector must be Nx1"); 
    	}

        int[] result = new int[vec.length];
        for (int i = 0; i < vec.length; i++) {
            int tmp = 0;
            for (int j = 0; j < vec.length; j++) {
                tmp = GF256.add(tmp, GF256.mult(matrix[i][j], vec[j]));
            }
            result[i] = tmp;
        }

        return result;
    }

    /**
     * Returns the <i>i<sup>th</sup></i> row of the matrix.
     * @param i index of the row to return
     * @return the <i>i<sup>th</sup></i> row of the matrix (starting at 0)
     */
    public int[] getRow(int i) {
        return matrix[i];
    }

    public void output() {
        System.err.println("matrix:");
        for (int[] tmp : matrix) {
            for (int i : tmp) {
                System.err.print(" " + i);
            }
            System.err.println("");
        }
    }

}
