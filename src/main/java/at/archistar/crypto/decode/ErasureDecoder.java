package at.archistar.crypto.decode;

import at.archistar.crypto.math.CustomMatrix;
import at.archistar.crypto.math.GF256;

/**
 * Reconstructs a polynomial from the given xy-pairs using the <i>Erasure Decoding</i> scheme.<br>
 * <b>NOTE</b>: This algorithm does assumes all passed points to be correct! 
 *              (use {@link BerlekampWelchDecoder} if you need fault tolerance)
 * 
 * @author Andreas Happe
 * @author Elias Frantar
 * @version 2014-7-25
 */
public class ErasureDecoder implements Decoder {
    private final CustomMatrix matrix;

    ErasureDecoder(int[] xValues) {
        int[][] matrixX = new int[xValues.length][xValues.length];

        for (int i = 0; i < xValues.length; i++) {
            for (int j = 0; j < xValues.length; j++) {
                matrixX[i][j] = GF256.pow(xValues[i], j);
            }
        }

        matrix = new CustomMatrix(new CustomMatrix(matrixX).computeInverse().getEncoded());
    }
    
    @Override
    public int[] decode(int[] y) {
        return matrix.rightMultiply(y);
    }
}
