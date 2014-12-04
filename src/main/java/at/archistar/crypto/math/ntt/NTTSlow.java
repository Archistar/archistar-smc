package at.archistar.crypto.math.ntt;

import at.archistar.crypto.math.GF;
import at.archistar.crypto.math.GenericMatrix;

/**
 * @author andy
 */
public class NTTSlow extends AbstractNTT {
    
    public NTTSlow(GF gf) {
        super(gf);
    }
    
    @Override
    public int[] ntt(int a[], int w) {
        int n = a.length;
        
        int matrix[][] = new int[n][n];
        
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < n; j++) {
                matrix[i][j] = gf.pow(gf.pow(w, i), j);
            }
        }
        
        return new GenericMatrix(matrix, gf).rightMultiply(a);
    }
}
