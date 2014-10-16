package at.archistar.crypto.decode;

import at.archistar.crypto.math.BCGF256;
import at.archistar.crypto.math.CustomMatrix;
import at.archistar.crypto.math.GF;

/**
 * Reconstructs a polynomial from the given xy-pairs using the <i>Erasure Decoding</i> scheme.<br>
 * <b>NOTE</b>: This algorithm does assumes all passed points to be correct! 
 *              (use {@link BerlekampWelchDecoder} if you need fault tolerance)
 */
public class ErasureDecoder implements Decoder {
    private final CustomMatrix matrix;
    
    private final int k;
    
    private static final BCGF256 backupBCFG = new BCGF256();
    
    ErasureDecoder(int[] xValues, int k, GF gf) {
        
        this.k = k;
        
        int[][] matrixX = new int[xValues.length][xValues.length];

        for (int i = 0; i < xValues.length; i++) {
            for (int j = 0; j < xValues.length; j++) {
                matrixX[i][j] = gf.pow(xValues[i], j);
            }
        }
        
        if (gf instanceof BCGF256) {
            matrix = new CustomMatrix(new CustomMatrix(matrixX, (BCGF256)gf).computeInverse().getEncoded(), (BCGF256)gf);
        } else {
            /* TODO: can we create a custom matrix with just GF? */
            matrix = new CustomMatrix(new CustomMatrix(matrixX, backupBCFG).computeInverse().getEncoded(), backupBCFG);
        }
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
