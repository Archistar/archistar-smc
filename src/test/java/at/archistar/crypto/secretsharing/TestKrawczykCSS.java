package at.archistar.crypto.secretsharing;

import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.random.FakeRandomSource;
import org.junit.Before;

/**
 * Test for {@link KrawczykCSS}
 */
public class TestKrawczykCSS extends BasicSecretSharingTest {

    public TestKrawczykCSS() {
        super(8, 5);
    }

    /* setup and tear-down */
    @Before
    public void setup() throws WeakSecurityException {
        algorithm = new KrawczykCSS(n, k, new FakeRandomSource());
    }
}
