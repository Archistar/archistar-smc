package at.archistar.crypto.math;

import de.flexiprovider.common.math.codingtheory.GF2mField;
import de.flexiprovider.common.math.linearalgebra.GF2mMatrix;
import de.flexiprovider.common.util.IntUtils;

/* TODO: we should probably remove all dependencies from flexiprovider and implement all methods to use GF256Math */

/**
 * <p>A matrix operating in GF(256).</p>
 * 
 * <p>Uses {@link GF256Math} for optimized operations and provides some additional methods in contrary to the flexiprovider-
 * class. </p>
 *
 * @author Elias Frantar <i>(added documentation, implemented additional methods)</i>
 * @author Andreas Happe <andreashappe@snikt.net>
 * @version 2014-7-14
 */
public class GF256Matrix extends GF2mMatrix {
	private static final GF2mField gf256 = new GF2mField(8, 0x11d); // Galois-Field (x^8 + x^4 + x^3 + x + 1 = 0) / 285
	
    /**
     * Constructor
     * @param data the data to put into the matrix
     */
	public GF256Matrix(int[][] data) {
        super(gf256, data);
    }

	/**
	 * Constructor
	 * @param encoded the encoded matrix (got via {@link #getEncoded()})
	 */
    public GF256Matrix(byte[] encoded) {
        super(gf256, encoded);
    }

    /**
     * Performs a matrix * vector multiplication.
     * 
     * <b>NOTE:</b> Matrix multiplication is not commutative. (A*B != B*A) and so does only work if A(MxN) and B(NxO).
     * 		 		Throws an {@link ArithmeticException} if this condition is violated.
     * 
     * @param vec the vector to multiply the matrix with (a 1D-matrix9
     * @return the product of the matrix and the given vector <i>(matrix * vector)</i>
     */
    public int[] rightMultiply(int vec[]) {
    	if(vec.length != matrix.length || vec.length != matrix[0].length) // multiplication only works if A(MxN) and B(NxO)
    		throw new ArithmeticException("when matrix is MxN, vector must be Nx1"); 

        int[] result = new int[vec.length];
        for (int i = 0; i < matrix.length; i++) {
            int tmp = 0;
            for (int j = 0; j < vec.length; j++)
                tmp = GF256Math.add(tmp, GF256Math.mult(matrix[i][j], vec[j]));
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
    
    /**
     * Computes the inverse of this matrix using <i>Gaussian elimination</i> and eliminating dependent rows. 
     * (which would otherwise not allow inversion).<br>
     * Therefore this method should be used for soling matrix-equations.
     * 
     * <p>Throws an {@link ArithmeticException} if the matrix is not invertible</p>
     * 
     * @return the inverse of this matrix (as a new matrix)
     */
    public GF256Matrix computeInverseElimDepRows() {
    	if (numRows != numColumns)
            throw new ArithmeticException("Matrix is not invertible.");

        // clone this matrix
        int[][] tmpMatrix = new int[numRows][numRows];
        for (int i = numRows - 1; i >= 0; i--)
            tmpMatrix[i] = IntUtils.clone(matrix[i]);

        // initialize inverse matrix as unit matrix
        int[][] invMatrix = new int[numRows][numRows];
        for (int i = numRows - 1; i >= 0; i--)
            invMatrix[i][i] = 1;

        // simultaneously compute Gaussian reduction of tmpMatrix and unit matrix
        for (int i = 0; i < numRows; i++) {
            // if diagonal element is zero
            if (tmpMatrix[i][i] == 0) {
                boolean foundNonZero = false;
                // find a non-zero element in the same column
                for (int j = i + 1; j < numRows; j++) {
                    if (tmpMatrix[j][i] != 0) {
                        // found it, swap rows ...
                        foundNonZero = true;
                        swapRows(tmpMatrix, i, j);
                        swapRows(invMatrix, i, j);
                        // ... and quit searching
                        j = numRows;
                        continue;
                    }
                }
                // if no non-zero element was found
                if (!foundNonZero) {
                    // this row is dependent so eliminate it with the corresponding column
                	numRows--; // this will only happen in the last row
                	numColumns--;
                }
            }

            // normalize i-th row
            int coef = tmpMatrix[i][i];
            int invCoef = field.inverse(coef);
            multRowWithElementThis(tmpMatrix[i], invCoef);
            multRowWithElementThis(invMatrix[i], invCoef);

            // normalize all other rows
            for (int j = 0; j < numRows; j++) {
                if (j != i) {
                    coef = tmpMatrix[j][i];
                    if (coef != 0) {
                        int[] tmpRow = multRowWithElement(tmpMatrix[i], coef);
                        int[] tmpInvRow = multRowWithElement(invMatrix[i], coef);
                        addToRow(tmpRow, tmpMatrix[j]);
                        addToRow(tmpInvRow, invMatrix[j]);
                    }
                }
            }
        }
        
        trim(invMatrix, numRows, numColumns);
        return new GF256Matrix(invMatrix);
    }
    
    /*
     * Helper-methods from for Gaussian elimination
     * @author flexiprovider
     */
    private static void swapRows(int[][] matrix, int first, int second) {
        int[] tmp = matrix[first];
        matrix[first] = matrix[second];
        matrix[second] = tmp;
    }
    private void multRowWithElementThis(int[] row, int element) {
        for (int i = row.length - 1; i >= 0; i--)
            row[i] = GF256Math.mult(row[i], element);
    }
    private int[] multRowWithElement(int[] row, int element) {
        int[] result = new int[row.length];
        
        for (int i = row.length - 1; i >= 0; i--)
        	result[i] = GF256Math.mult(row[i], element);

        return result;
    }
    private void addToRow(int[] fromRow, int[] toRow) {
        for (int i = toRow.length - 1; i >= 0; i--)
            toRow[i] = GF256Math.add(fromRow[i], toRow[i]);
    }
    
    private void trim(int[][] matrix, int newRows, int newColumns) {
    	int[][] newMatrix = new int[newRows][newColumns];
    	
    	for (int i = 0; i < newRows; i++)
    		for (int j = 0; j < newColumns; j++)
    			newMatrix[i][j] = matrix[i][j];
    	
    	matrix = newMatrix;
    }
}