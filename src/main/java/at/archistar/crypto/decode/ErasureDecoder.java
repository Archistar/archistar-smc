package at.archistar.crypto.decode;

import at.archistar.crypto.exceptions.ImpossibleException;
import at.archistar.crypto.math.GF256Matrix;
import at.archistar.crypto.math.GF256Math;

/**
 * Reconstructs a polynomial from the given xy-pairs using the <i>Erasure Decoding</i> scheme.<br>
 * <b>NOTE</b>: This algorithm does assumes all passed points to be correct! 
 * 				(use {@link BerlekampWelchDecoder} if you need fault tolerance)
 * 
 * @author Elias Frantar
 * @version 2014-7-16
 */
public class ErasureDecoder extends PolySolver {
	private GF256Matrix matrix;
	
	@Override
	public void prepare(int[] x) {
		int[][] matrixX = new int[x.length][x.length];
		for (int i = 0; i < x.length; i++)
			for (int j = 0; j < x.length; j++)
				matrixX[i][j] = GF256Math.pow(x[i], j);

		matrix = new GF256Matrix(new GF256Matrix(matrixX).computeInverse().getEncoded());
		prepared = true;
    }

	@Override
	public int[] solve(int[] y) {
		if(!prepared)
			throw new ImpossibleException("Solve has not been prepared properly!");
		
		return matrix.rightMultiply(y);
	}
}