package at.archistar.crypto.decode;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import at.archistar.crypto.exceptions.ImpossibleException;
import at.archistar.crypto.math.CustomMatrix;
import at.archistar.crypto.math.GF256;

/**
 * Reconstructs a polynomial from the given xy-pairs using the <i>Erasure Decoding</i> scheme.<br>
 * <b>NOTE</b>: This algorithm does assumes all passed points to be correct! 
 *              (use {@link BerlekampWelchDecoder} if you need fault tolerance)
 * 
 * @author Elias Frantar
 * @version 2014-7-25
 */
public class ErasureDecoder extends PolySolver {
    private CustomMatrix matrix;
    
    @Override
    public void prepare(int[] x) {
        int[][] matrixX = new int[x.length][x.length];

        for (int i = 0; i < x.length; i++) {
            for (int j = 0; j < x.length; j++) {
                matrixX[i][j] = GF256.pow(x[i], j);
            }
        }

        matrix = new CustomMatrix(new CustomMatrix(matrixX).computeInverse().getEncoded());
        prepared = true;
    }

    /** TODO: why is x (and thus matrix) not assigend within constructor */
    @Override
    @SuppressFBWarnings("UWF_FIELD_NOT_INITIALIZED_IN_CONSTRUCTOR")
    public int[] solve(int[] y) {
        if (!prepared) {
            throw new ImpossibleException("Solve has not been prepared properly!");
        }
        
        return matrix.rightMultiply(y);
    }
}
