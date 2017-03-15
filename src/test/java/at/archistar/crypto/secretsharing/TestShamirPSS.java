package at.archistar.crypto.secretsharing;

import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.decode.ErasureDecoderFactory;
import org.junit.Before;
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
        DecoderFactory df = new ErasureDecoderFactory();
        algorithm = new ShamirPSS(n, k, new FakeRandomSource(), df);
    }
}
