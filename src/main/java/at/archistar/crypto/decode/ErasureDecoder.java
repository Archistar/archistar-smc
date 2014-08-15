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
    
    private final int k;

    ErasureDecoder(int[] xValues, int k) {
        
        this.k = k;
        
        int[][] matrixX = new int[xValues.length][xValues.length];

        for (int i = 0; i < xValues.length; i++) {
            for (int j = 0; j < xValues.length; j++) {
                matrixX[i][j] = GF256.pow(xValues[i], j);
            }
        }

        matrix = new CustomMatrix(new CustomMatrix(matrixX).computeInverse().getEncoded());
    }
    
    @Override
    public int[] decode(int[] y, int errorCount) throws UnsolvableException {
        if (errorCount != 0) {
            throw new UnsolvableException("Erasuredecoder cannot fix errors");
        }
        
        if (matrix.getNumRows() != y.length) {
            throw new UnsolvableException("Different Lengths");
        }

        
        if (k > matrix.getNumRows()) {
            throw new UnsolvableException("Seems to be a Configuraiton error");
        }
        
        return matrix.rightMultiply(y);
    }
}
