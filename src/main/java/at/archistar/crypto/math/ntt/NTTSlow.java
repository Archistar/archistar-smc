package at.archistar.crypto.math.ntt;

import at.archistar.crypto.math.GFFactory;

/**
 * Helper class for performing NTT operations
 */
public class NTTSlow extends AbstractNTT {
    
    /** initialize helper class
     * 
     * @param gffactory the mathematical field within which all operations should be
     *                  performed
     */
    public NTTSlow(GFFactory gffactory) {
        super(gffactory);
    }

    /**
     * Perform an ntt
     * 
     * @param a incoming data
     * @param w generator
     * @return ntt(a)
     */
    @Override
    public int[] ntt(int a[], int w) {
        int n = a.length;
        
        int matrix[][] = new int[n][n];
        
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < n; j++) {
                matrix[i][j] = gf.pow(gf.pow(w, i), j);
            }
        }
        
        return gffactory.createMatrix(matrix).rightMultiply(a);
    }
}
