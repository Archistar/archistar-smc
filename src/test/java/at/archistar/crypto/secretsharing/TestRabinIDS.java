package at.archistar.crypto.secretsharing;

import org.junit.Before;

import at.archistar.crypto.exceptions.WeakSecurityException;

/**
 * Tests for {@link RabinBenOrRSS}
 */
public class TestRabinIDS extends BasicSecretSharingTest {
    
    public TestRabinIDS() {
        super(8, 3);
    }

    @Before
    public void setup() throws WeakSecurityException {
        algorithm = new RabinIDS(n, k);
    }
}
