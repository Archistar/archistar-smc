package at.archistar.crypto;

import at.archistar.crypto.data.InvalidParametersException;
import at.archistar.crypto.data.PSSShare;
import at.archistar.crypto.data.ReconstructionResult;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.random.FakeRandomSource;
import at.archistar.crypto.random.RandomSource;
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
public class TestPSSEngine {

    private final static RandomSource rng = new FakeRandomSource();
    private final byte data[] = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private final int n = 8;
    private final int k = 5;
    private CryptoEngine algorithm;

    /**
     * create a new Shamir CryptoEngine
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

    @Test
    public void reconstructWithOneCorruptedShare() throws ReconstructionException {
        Share[] shares = algorithm.share(data);
        assertThat(shares.length).isEqualTo(n);

        shares[1].getYValues()[1] = (byte) (shares[1].getYValues()[1] + 1);

        ReconstructionResult result = algorithm.reconstruct(shares);
        assertThat(result.getData()).isEqualTo(data);
        assertThat(result.getErrors().size()).isEqualTo(1);
    }

    @Test
    public void reconstructWithTCorruptedShares() throws ReconstructionException {
        Share[] shares = algorithm.share(data);
        assertThat(shares.length).isEqualTo(n);

        for (int i = 0; i < (n - k); i++) {
            shares[i].getYValues()[0] = (byte) (shares[i].getYValues()[0] + 1);
        }

        ReconstructionResult result = algorithm.reconstruct(shares);
        assertThat(result.getData()).isEqualTo(data);
        assertThat(result.getErrors().size()).isEqualTo(n - k);
    }

    @Test
    public void failWithTPlusOneCorruptedShares() throws ReconstructionException {
        Share[] shares = algorithm.share(data);
        assertThat(shares.length).isEqualTo(n);

        for (int i = 0; i <= (n - k); i++) {
            shares[i].getYValues()[0] = (byte) (shares[i].getYValues()[0] + 1);
        }

        ReconstructionResult result = algorithm.reconstruct(shares);
        assertThat(result.isOkay()).isFalse();
        assertThat(result.getErrors().size()).isGreaterThan(n - k);
    }
}
