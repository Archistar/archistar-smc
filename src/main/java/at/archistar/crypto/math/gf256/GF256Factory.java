package at.archistar.crypto.math.gf256;

import at.archistar.crypto.math.GF;
import at.archistar.crypto.math.GFFactory;
import at.archistar.crypto.math.GFMatrix;
import at.archistar.crypto.math.GenericMatrix;

/**
 *
 * @author andy
 */
public class GF256Factory implements GFFactory {
    
    private static final GF256 GF256 = new GF256();
    
    @Override
    public GF createHelper() {
        return GF256;
    }
    
    @Override
    public GFMatrix createMatrix(int matrix[][]) {
        return new GenericMatrix(matrix, GF256);
    }
}
