package at.archistar.crypto.decode;

import at.archistar.crypto.math.GFMatrix;
import at.archistar.crypto.math.GF;
import at.archistar.crypto.math.GFFactory;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

/**
 * Reconstructs a polynomial from the given xy-pairs using the <i>Erasure Decoding</i> scheme.<br>
 * <b>NOTE</b>: This algorithm does assumes all passed points to be correct! 
 *              (use {@link BerlekampWelchDecoder} if you need fault tolerance)
 */
public class ErasureDecoder implements Decoder {
    
    private final GFMatrix matrix;
    
    private final int k;
    
    /**
     * create a new ErasureDecoder
     * @param xValues the known xValues
     * @param k how many elements will be expected for reconstruction
     * @param gffactory within which field will be performing our operations
     */
    public ErasureDecoder(final int[] xValues, final int k, final GFFactory gffactory) {
        
        this.k = k;
        final GF gf = gffactory.createHelper();
        
        final int[][] matrixX = new int[k][k];

        for (int i = 0; i < k; i++) {
            for (int j = 0; j < k; j++) {
                matrixX[i][j] = gf.pow(xValues[i], j);
            }
        }
        
        matrix = gffactory.createMatrix(matrixX).inverse();
    }
    
    /**
     * Decode y (with an maximal error count of errorCount
     * 
     * @return the decoded values
     */
    @Override
    @SuppressFBWarnings("EI_EXPOSE_REP")
    public int[] decode(final int[] y, final int errorCount) throws UnsolvableException {
        
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
    
    /**
     * this version of decode should be faster, but does not check any input
     * parameters for validity
     * 
     * @return the decoded data filled in within the original target parameter
     */
    @Override
    public int[] decodeUnsafe(final int[] target, final int[] y, final int errorCount) throws UnsolvableException {
        return matrix.rightMultiplyInto(target, y);
    }    
}
