package at.archistar.crypto.math.ntt;

import at.archistar.crypto.math.GF;
import at.archistar.crypto.math.gf257.GF257;
import java.util.Random;
import org.junit.Test;

import static org.fest.assertions.api.Assertions.*;
import org.junit.Ignore;

/**
 * @author andy
 */
public class ExhaustiveNTTTest {

    private static final int w = 241;
    
    private static final GF gf257 = new GF257();
    
    @Test
    @Ignore("very slow")
    public void testAllValues4() {
        AbstractNTT ntt = new NTTSlow(gf257);
        int[] tmp = new int[4];
        Random random = new Random();
        
        for (int i = 0; i < 257; i++) {
            tmp[0] = i;
            for (int j = 0; j < 257; j++) {
                System.out.println("runde: " + i + " / " + j);
                tmp[1] = j;
                for (int k = 0; k < 257; k++) {
                    tmp[2] = k;
                    for (int l = 0; l < 257; l++) { 
                        tmp[3] = l;
                        
                        int[] tmpOut = ntt.ntt(tmp, w);
                        assertThat(ntt.intt(tmpOut, w)).isEqualTo(tmp);
                    }
                }
            }
        }
    }
    
    @Test
    @Ignore("very slow")
    public void testSameTextbookAndSlow() {
        int[] tmp = new int[4];
        Random random = new Random();
        
        AbstractNTT nttSlow = new NTTSlow(gf257);
        AbstractNTT nttTextbook = new NTTTextbook(gf257);
        
        for (int i = 0; i < 257; i++) {
            tmp[0] = i;
            for (int j = 0; j < 257; j++) {
                System.out.println("runde: " + i + " / " + j);
                tmp[1] = j;
                for (int k = 0; k < 257; k++) {
                    tmp[2] = k;
                    for (int l = 0; l < 257; l++) { 
                        tmp[3] = l;
                        
                        int[] tmpOut = nttSlow.ntt(tmp, w);
                        assertThat(tmpOut).isEqualTo(nttTextbook.ntt(tmp, w));
                        assertThat(nttSlow.intt(tmpOut, w)).isEqualTo(nttTextbook.intt(tmpOut, w));
                    }
                }
            }
        }
    }
}