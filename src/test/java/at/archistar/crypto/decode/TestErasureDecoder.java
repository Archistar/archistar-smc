package at.archistar.crypto.decode;

import at.archistar.crypto.math.GFFactory;
import at.archistar.crypto.math.gf257.GF257Factory;
import at.archistar.crypto.secretsharing.NTTShamirPSS;
import org.bouncycastle.util.Arrays;
import static org.fest.assertions.api.Assertions.assertThat;
import org.junit.Test;

/**
 *
 * @author andy
 */
public class TestErasureDecoder {
    
   /**
     * test if a GF257 Decoder can be built
     */
    @Test
    public void tryBuildGF257Decoder() {
        final int NTTBlockLength = 256;
        final int n = 7;
        final int k = 3;
        final int minLength = (NTTBlockLength/n)*k;
        
        final GFFactory gf257factory = new GF257Factory();
        int[] xValues = NTTShamirPSS.prepareXValuesFor(minLength, gf257factory.createHelper());
        
        /* limit to k results */
        int[] resultXValues = Arrays.copyOf(xValues, minLength);
        
        /* create decoder */
        Decoder decoder = new ErasureDecoder(resultXValues, minLength, gf257factory);
        assertThat(decoder).isNotNull();
    }
}
