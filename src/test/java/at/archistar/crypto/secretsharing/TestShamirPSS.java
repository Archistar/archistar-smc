package at.archistar.crypto.secretsharing;

import org.junit.Before;
import at.archistar.crypto.exceptions.WeakSecurityException;
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
        algorithm = new ShamirPSS(n, k, new FakeRandomSource());
    }
}
