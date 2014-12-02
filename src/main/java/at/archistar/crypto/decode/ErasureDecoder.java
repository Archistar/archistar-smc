package at.archistar.crypto.decode;

import at.archistar.crypto.math.GFMatrix;
import at.archistar.crypto.math.GF;
import at.archistar.crypto.math.GFFactory;

/**
 * Reconstructs a polynomial from the given xy-pairs using the <i>Erasure Decoding</i> scheme.<br>
 * <b>NOTE</b>: This algorithm does assumes all passed points to be correct! 
 *              (use {@link BerlekampWelchDecoder} if you need fault tolerance)
 */
public class ErasureDecoder implements Decoder {
    private final GFMatrix matrix;
    
    private final int k;
    
    public ErasureDecoder(int[] xValues, int k, GFFactory gffactory) {
        
        this.k = k;
        GF gf = gffactory.createHelper();
        
        int[][] matrixX = new int[k][k];

        for (int i = 0; i < k; i++) {
            for (int j = 0; j < k; j++) {
                matrixX[i][j] = gf.pow(xValues[i], j);
            }
        }
        
        matrix = gffactory.createMatrix(matrixX).inverse();
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
