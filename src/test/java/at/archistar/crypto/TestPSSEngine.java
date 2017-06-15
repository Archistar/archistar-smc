package at.archistar.crypto;

import at.archistar.crypto.data.InvalidParametersException;
import at.archistar.crypto.data.PSSShare;
import at.archistar.crypto.data.ReconstructionResult;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.secretsharing.ReconstructionException;
import at.archistar.crypto.secretsharing.WeakSecurityException;
import org.junit.Before;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;

import static org.fest.assertions.api.Assertions.assertThat;

/**
 * Tests for {@link PSSEngine}
 */
public class TestPSSEngine extends AbstractEngineTest {

    /**
     * create a new PSS CryptoEngine
     *
     * @throws WeakSecurityException should not happen due to fixed setup
     * @throws NoSuchAlgorithmException should not happen due to fixed setup
     */
    @Before
    public void setup() throws WeakSecurityException, NoSuchAlgorithmException {
        algorithm = new PSSEngine(n, k, rng);
    }

    @Test
    public void reconstructPartialShares() throws InvalidParametersException, ReconstructionException {
        Share[] shares = algorithm.share(data);
        assertThat(shares.length).isEqualTo(n);
        Share[] truncated = new Share[n];
        for (int i = data.length + 1; i > 0; i--) {
            for (int s = 0; s < n; s++) {
                truncated[s] = new PSSShare((byte) shares[s].getX(), Arrays.copyOf(shares[s].getYValues(), i),
                        new HashMap<>(), new HashMap<>());
            }
            ReconstructionResult reconstructed = algorithm.reconstructPartial(truncated, 0);
            assertThat(reconstructed.getData()).isEqualTo(Arrays.copyOf(data, i));
        }
    }
}
