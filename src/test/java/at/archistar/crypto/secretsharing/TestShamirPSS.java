package at.archistar.crypto.secretsharing;

import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.decode.ErasureDecoderFactory;
import org.junit.Before;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.math.GF;
import at.archistar.crypto.math.GFFactory;
import at.archistar.crypto.math.gf256.GF256Factory;
import at.archistar.crypto.random.FakeRandomSource;

/**
 * Tests for {@link ShamirPSS}.
 */
public class TestShamirPSS extends BasicSecretSharingTest {

    public TestShamirPSS() {
        super(8, 3);
    }

    @Before
    public void setup() throws WeakSecurityException {
        GFFactory gffactory = new GF256Factory();
        DecoderFactory df = new ErasureDecoderFactory(gffactory);
        GF gf = gffactory.createHelper();
        
        algorithm = new ShamirPSS(n, k, new FakeRandomSource(), df, gf);
    }
}
