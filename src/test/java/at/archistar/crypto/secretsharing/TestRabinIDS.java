package at.archistar.crypto.secretsharing;

import at.archistar.crypto.data.Share;
import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.decode.ErasureDecoderFactory;
import org.junit.Before;

import at.archistar.crypto.math.GF;
import at.archistar.crypto.math.GFFactory;
import at.archistar.crypto.math.gf256.GF256Factory;
import org.junit.Test;

import java.io.IOException;

import static org.fest.assertions.api.Assertions.assertThat;

/**
 * Tests for {@link RabinBenOrRSS}
 */
public class TestRabinIDS extends BasicSecretSharingTest {

    public TestRabinIDS() {
        super(8, 3);
    }

    @Before
    public void setup() throws WeakSecurityException {

        GFFactory gffactory = new GF256Factory();
        DecoderFactory df = new ErasureDecoderFactory(gffactory);
        GF gf = gffactory.createHelper();

        algorithm = new RabinIDS(n, k, df, gf);
    }

    @Test
    public void it_produces_shares_of_the_right_size() throws IOException {
        final Share[] shares = algorithm.share(data);
        final int new_length = data.length % k == 0 ? data.length / k : (data.length / k) + 1;
        for (Share s : shares) {
            assertThat(s.getYValues().length).isEqualTo(new_length);
        }
    }
}
