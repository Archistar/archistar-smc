package at.archistar.crypto;

import at.archistar.crypto.data.CSSShare;
import at.archistar.crypto.data.InvalidParametersException;
import at.archistar.crypto.data.ReconstructionResult;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.informationchecking.RabinBenOrRSS;
import at.archistar.crypto.secretsharing.ReconstructionException;
import at.archistar.crypto.secretsharing.WeakSecurityException;
import org.junit.Before;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.fest.assertions.api.Assertions.assertThat;

/**
 * Tests for {@link RabinBenOrRSS}
 */
public class TestCSSEngine extends AbstractEngineTest {

    /**
     * create a new CSS CryptoEngine
     *
     * @throws WeakSecurityException should not happen due to fixed setup
     * @throws NoSuchAlgorithmException should not happen due to fixed setup
     */
    @Before
    public void setup() throws WeakSecurityException, NoSuchAlgorithmException {
        algorithm = new CSSEngine(n, k, rng);
    }

    /**
     * test the reconstruction of partial shares by chopping off all possible parts
     * of the shared data; therefore, reconstruction happens in increments of k
     * (the index computations required for byte-precise access are the responsibility
     * of the client)
     */
    @Test
    public void reconstructPartialShares() throws InvalidParametersException, ReconstructionException {
        Share[] shares = algorithm.share(data);
        assertThat(shares.length).isEqualTo(n);
        Share[] truncated = new Share[n];
        int sharedLength = shares[0].getYValues().length;
        for (int i = 0; i < sharedLength; i++) {
            for (int j = i + 1; j <= sharedLength; j++) {
                for (int s = 0; s < n; s++) {
                    Share share = shares[s];
                    truncated[s] = new CSSShare((byte) share.getX(), Arrays.copyOfRange(share.getYValues(), i, j),
                            ((CSSShare) share).getFingerprints(), share.getOriginalLength(), 1,
                            ((CSSShare) share).getKey());
                }
                ReconstructionResult reconstructed = algorithm.reconstructPartial(truncated, i * k);
                int trunc_begin = i * k;
                int trunc_end = Math.min(data.length, j * k);
                int truncation = j * k > data.length ? data.length - (i * k) : (j - i) * k;
                // truncation of the reconstructed data is actually only needed when we are on the last block
                assertThat(Arrays.copyOf(reconstructed.getData(), truncation)).isEqualTo(Arrays.copyOfRange(data, trunc_begin, trunc_end));
            }
        }
    }

    @Test
    public void recovery() throws ReconstructionException {
        Share[] shared = algorithm.share(data);
        Map<Byte, byte[]> fp = ((CSSShare) shared[0]).getFingerprints();
        for (int i = 0; i <= n - k; i++) {
            List<Share> corrupted = Arrays.asList(algorithm.share(data));
            Collections.shuffle(corrupted);
            for (int j = 0; j < i; j++) {
                corrupted.get(j).getYValues()[0] = (byte) (corrupted.get(j).getYValues()[0] + 1);
            }
            Share[] recovered = algorithm.recover(corrupted.toArray(new Share[0]));
            assertThat(recovered.length).isEqualTo(i);
            for (Share recov : recovered) {
                assertThat(recov.getYValues()).isEqualTo(shared[recov.getId() - 1].getYValues());
                assertThat(recov).usingComparator(Share::compareTo).isEqualTo(shared[recov.getId() - 1]);
            }
        }
    }
}
