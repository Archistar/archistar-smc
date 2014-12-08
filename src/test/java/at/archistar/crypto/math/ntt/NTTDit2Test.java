package at.archistar.crypto.math.ntt;

import at.archistar.crypto.math.gf257.GF257Factory;
import static org.fest.assertions.api.Assertions.assertThat;
import org.junit.Test;

/**
 *
 * @author andy
 */
public class NTTDit2Test {
    
    @Test
    public void nttDit2SameAsTextbook() {
        final GF257Factory gf257 = new GF257Factory();
        final int[] data =  {1, 1, 1, 0};
        final int[] result = {3, 241, 1, 16};
        final int w = 241;
        
        AbstractNTT textbook = new NTTTextbook(gf257);
        NTTDit2 dit2 = new NTTDit2(gf257);
        
        assertThat(textbook.ntt(data, w)).isEqualTo(result);
        int tmp[] = data.clone();
        assertThat(dit2.ntt(tmp, tmp.length, 2, 1)).isEqualTo(result);
        tmp = data.clone();
        assertThat(dit2.ntt(data, w)).isEqualTo(result);
        assertThat(tmp).isEqualTo(data);
    }
}