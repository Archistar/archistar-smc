package at.archistar.crypto.math.gf257;

import at.archistar.crypto.math.GF;
import at.archistar.crypto.math.GFFactory;
import at.archistar.crypto.math.GFMatrix;
import at.archistar.crypto.math.GenericMatrix;

/**
 *
 * @author andy
 */
public class GF257Factory implements GFFactory {
    
    private static final GF257 GF257 = new GF257();
    
    @Override
    public GF createHelper() {
        return GF257;
    }
    
    @Override
    public GFMatrix createMatrix(int matrix[][]) {
        return new GenericMatrix(matrix, GF257);
    }
}
