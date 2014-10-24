package at.archistar.crypto.math;

import at.archistar.crypto.math.gf257.GF257;
import org.junit.Test;

/**
 * @author andy
 */
public class TestGF257 {
    
    @Test
    public void testInverse() {
        GF257 gf = new GF257();
        for (int i=1; i < 257; i++) {
            assert( gf.mult(gf.inverse(i),i) == 1);
        }
    }
}
