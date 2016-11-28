package at.archistar.crypto;

import at.archistar.crypto.data.InvalidParametersException;
import at.archistar.crypto.data.ShamirShare;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.random.FakeRandomSource;
import at.archistar.crypto.random.RandomSource;
import at.archistar.crypto.secretsharing.ReconstructionException;
import at.archistar.crypto.secretsharing.WeakSecurityException;
import org.junit.Before;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static org.fest.assertions.api.Assertions.assertThat;

/**
 * Tests for {@link at.archistar.crypto.ShamirEngine}
 */
public class TestShamirEngine {

    private final byte data[] = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private final int n = 8;
    private final int k = 5;
    private final static RandomSource rng = new FakeRandomSource();
    private CryptoEngine algorithm;

    /**
     * create a new RabinBenOr CryptoEngine
     *
     * @throws WeakSecurityException should not happen due to fixed setup
     * @throws NoSuchAlgorithmException should not happen due to fixed setup
     */
    @Before
    public void setup() throws WeakSecurityException, NoSuchAlgorithmException {
        algorithm = new ShamirEngine(n, k, rng);
    }

    @Test
    public void reconstructPartialShares() throws InvalidParametersException, ReconstructionException {
        Share[] shares = algorithm.share(data);
        assertThat(shares.length).isEqualTo(n);
        Share[] truncated = new Share[n];
        for (int i = data.length + 1; i > 0; i--) {
            for (int s = 0; s < n; s++) {
                truncated[s] = new ShamirShare((byte) shares[s].getX(), Arrays.copyOf(shares[s].getYValues(), i));
            }
            byte[] reconstructed = algorithm.reconstructPartial(truncated);
            assertThat(reconstructed).isEqualTo(Arrays.copyOf(data, i));
        }
    }
}
