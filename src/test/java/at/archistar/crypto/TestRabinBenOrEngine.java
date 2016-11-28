package at.archistar.crypto;

import at.archistar.crypto.data.InvalidParametersException;
import at.archistar.crypto.data.KrawczykShare;
import at.archistar.crypto.informationchecking.RabinBenOrRSS;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.secretsharing.ReconstructionException;
import at.archistar.crypto.secretsharing.WeakSecurityException;
import at.archistar.crypto.random.FakeRandomSource;
import at.archistar.crypto.random.RandomSource;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;

import static org.fest.assertions.api.Assertions.*;

import org.junit.Before;
import org.junit.Test;

/**
 * Tests for {@link RabinBenOrRSS}
 */
public class TestRabinBenOrEngine {

    private final byte data[] = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17};
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
        algorithm = new RabinBenOrEngine(n, k, rng);
    }

    /**
     * After a simple share+reconstruct step the reconstructed data should be
     * the same as the original data
     *
     * @throws WeakSecurityException should not happen due to fixed setup
     * @throws ReconstructionException should not happen due to fixed setup
     */
    @Test
    public void simpleShareReconstructRound() throws ReconstructionException, WeakSecurityException {
        Share shares[] = algorithm.share(data);
        assertThat(shares.length).isEqualTo(n);
        byte reconstructedData[] = algorithm.reconstruct(shares);
        assertThat(reconstructedData).isEqualTo(data);
    }

    /**
     * Reconstruct should work as long as share count > k
     *
     * @throws WeakSecurityException should not happen due to fixed setup
     * @throws ReconstructionException should not happen due to fixed setup
     */
    @Test
    public void reconstructWithSufficientSubSet() throws ReconstructionException, WeakSecurityException {
        Share shares[] = algorithm.share(data);

        for (int i = k + 1; i < n; i++) {
            Share shares1[] = Arrays.copyOfRange(shares, 0, i);
            byte reconstructedData[] = algorithm.reconstruct(shares1);
            assertThat(reconstructedData).isEqualTo(data);
        }
    }

    /**
     * Reconstruct should work with shuffled shares
     *
     * @throws WeakSecurityException should not happen due to fixed setup
     * @throws ReconstructionException should not happen due to fixed setup
     */
    @Test
    public void reconstructShuffledShares() throws ReconstructionException, WeakSecurityException {
        Share shares[] = algorithm.share(data);
        Collections.shuffle(Arrays.asList(shares));

        byte reconstructedData[] = algorithm.reconstruct(shares);
        assertThat(reconstructedData).isEqualTo(data);
    }

    /**
     * Reconstruct should fail if insufficient shares were provided
     *
     * @throws WeakSecurityException should not happen due to fixed setup
     */
    @Test
    public void notEnoughSharesTest() throws WeakSecurityException {
        Share shares[] = algorithm.share(data);

        for (int i = 0; i < k; i++) {
            Share[] shares1 = Arrays.copyOfRange(shares, 0, i);

            try {
                algorithm.reconstruct(shares1);
                fail("reconstruct with less than k shares did work. How?");
            } catch (ReconstructionException ex) {
                // this is actually the good case
            }
        }
    }

    @Test
    public void it_produces_shares_of_the_right_size() throws IOException {
        final Share[] shares = algorithm.share(data);
        final int new_length = data.length % k == 0 ? data.length / k : (data.length / k) + 1;
        for (Share s : shares) {
            assertThat(s.getYValues().length).isEqualTo(new_length);
        }
    }

    @Test
    public void reconstructPartialShares() throws InvalidParametersException, ReconstructionException {
        Share[] shares = algorithm.share(data);
        assertThat(shares.length).isEqualTo(n);
        Share[] truncated = new Share[n];
        int sharedLength = shares[0].getYValues().length;
        for (int i = sharedLength + 1; i > 0; i--) {
            for (int s = 0; s < n; s++) {
                assert(shares[s] instanceof KrawczykShare);
                KrawczykShare share = (KrawczykShare) shares[s];
                truncated[s] = new KrawczykShare((byte) share.getX(), Arrays.copyOf(share.getYValues(), i),
                        share.getOriginalLength(), 1, share.getKey());
            }
            byte[] reconstructed = algorithm.reconstructPartial(truncated);
            int truncation = Math.min(data.length, i % k == 0 ? i * k : i * (k - 1));
            // truncation of the reconstructed data is actually only needed when we are on the last block
            assertThat(Arrays.copyOf(reconstructed, truncation)).isEqualTo(Arrays.copyOf(data, truncation));
        }
    }
}
