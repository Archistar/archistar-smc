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
           {new NTTSlow(gf257), new int[] {1, 1, 1, 0}, new int[] {3, 241, 1, 16}},
           {new NTTTextbook(gf257), new int[] {1, 1, 1, 0}, new int[] {3, 241, 1, 16}},
        };
        return Arrays.asList(data);
    }
    
    private final int[] input;
    private final int[] output;
    private final AbstractNTT ntt;

    public NTTTest(AbstractNTT ntt, int[] input, int[] output) {
        this.ntt = ntt;
        this.input = input;
        this.output = output;
    }

    @Test
    public void simpleTest() {
        assertThat(ntt.ntt(input, 241)).isEqualTo(output);
    }
}