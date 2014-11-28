package at.archistar.crypto.math.ntt;

import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.math.GF;
import at.archistar.crypto.math.gf257.GF257;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Random;
import org.junit.Test;

import static org.fest.assertions.api.Assertions.*;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 * @author andy
 */
@RunWith(value = Parameterized.class)
public class NTTTest {

    /* existing nth primitive roots for GF(257) */
    /* FIXME: we take first root from sage implementation. Future versions    */
    /* should check if w is primitive nth root of unity for given vector      */
    /* lenght or calculate it for the input field                             */
    private final int[][] primitiveRootsOfUnity = new int[][] 
        {{2, 256},  
        {4, 241}, 
        {8, 64},
        {16, 249},
        {32, 136},
        {64, 81}, 
        {128, 9},
        {256, 3}};
        
    @Parameterized.Parameters
    public static Collection<Object[]> data() throws WeakSecurityException, NoSuchAlgorithmException {
        
        GF gf257 = new GF257();
        
        Object[][] data = new Object[][]{
           {new NTTSlow(gf257), 241, new int[] {1, 1, 1, 0}, new int[] {3, 241, 1, 16}},
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
    
    @Test
    public void testRandomValues() {
        
        int testcase = 7; // 256th root of unity is 3
        int vecLen = primitiveRootsOfUnity[testcase][0];
        int wLocal = primitiveRootsOfUnity[testcase][1];
        
        int[] tmp = new int[vecLen];
        Random random = new Random();
        
        for (int i = 0; i < 10; i++) {
            for (int j =0; j < vecLen; j++) {
                tmp[j] = random.nextInt(257);
            }
            
            int[] tmpOut = ntt.ntt(tmp, wLocal);
            assertThat(ntt.intt(tmpOut, wLocal)).isEqualTo(tmp);
        }
    }
}