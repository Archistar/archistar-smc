package at.archistar.crypto.math.ntt;

import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.math.GF;
import at.archistar.crypto.math.gf257.GF257;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;
import org.junit.Test;

import static org.fest.assertions.api.Assertions.*;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 * @author andy
 */
@RunWith(value = Parameterized.class)
public class NTTTest {
    
    @Parameterized.Parameters
    public static Collection<Object[]> data() throws WeakSecurityException, NoSuchAlgorithmException {
        
        GF gf257 = new GF257();
        
        Object[][] data = new Object[][]{
           {new NTTSlow(gf257), 241, new int[] {1, 1, 1, 0}, new int[] {3, 241, 1, 16}},
            {new NTTSlow(gf257), 1, new int[] {1, 1, 1, 1, 1}, new int[] {3, 241, 1, 16}},
           {new NTTTextbook(gf257), 241, new int[] {1, 1, 1, 0}, new int[] {3, 241, 1, 16}},
        };
        return Arrays.asList(data);
    }
    
    private final int[] input;
    private final int[] output;
    private final AbstractNTT ntt;
    private final int w;

    public NTTTest(AbstractNTT ntt, int w, int[] input, int[] output) {
        this.ntt = ntt;
        this.input = input;
        this.output = output;
        this.w = w;
    }

    @Test
    public void simpleNTTTest() {
        assertThat(ntt.ntt(input, w)).isEqualTo(output);
    }
    
    @Test
    public void simpleInverseNTTTest() {
        assertThat(ntt.intt(output, w)).isEqualTo(input);
    }

}