package at.archistar.crypto.secretsharing;

import at.archistar.TestHelper;
import at.archistar.crypto.data.Share;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import static org.fest.assertions.api.Assertions.assertThat;
import static org.fest.assertions.api.Assertions.fail;

import org.junit.Test;

/**
 * all secret-sharing algorithms should at least provide this functionality
 */
public abstract class BasicSecretSharingTest {

    protected BaseSecretSharing algorithm;
    protected final byte data[] = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    protected final int n;
    protected final int k;

    public BasicSecretSharingTest(int n, int k) {
        this.n = n;
        this.k = k;
    }

    @Test
    public void itReconstructsTheData() throws ReconstructionException {
        Share shares[] = algorithm.share(data);

        byte reconstructedData[] = algorithm.reconstruct(shares);
        assertThat(reconstructedData).isEqualTo(data);
    }

    @Test
    public void itReconstructsSubsetsOfShares() throws ReconstructionException {

        Share shares[] = algorithm.share(data);

        for (int i = k; i < n; i++) {
            Share[] shares1 = Arrays.copyOf(shares, i);
            byte reconstructedData[] = algorithm.reconstruct(shares1);
            assertThat(reconstructedData).isEqualTo(data);
        }
    }

    @Test
    public void itReconstructsShuffledShares() throws ReconstructionException {
        Share shares[] = algorithm.share(data);
        Collections.shuffle(Arrays.asList(shares));
        byte reconstructedData[] = algorithm.reconstruct(shares);
        assertThat(reconstructedData).isEqualTo(data);
    }

    @Test(expected = ReconstructionException.class)
    public void itFailsWhenThereAreTooFewShares() throws ReconstructionException {
        Share shares[] = algorithm.share(data);
        for (int i = 0; i < k; i++) {
            Share[] shares1 = Arrays.copyOf(shares, i);
            algorithm.reconstruct(shares1);
            fail("too few shares to reconstruct, what was returned?");
        }
    }

    @Test
    public void itStoresEmptyData() {
        Share[] shares = algorithm.share(new byte[0]);
        Share[] shares2 = algorithm.share(null);
        assertThat(shares).isNotEmpty();
        assertThat(shares2).isNotEmpty();
    }

    @Test
    public void itRecoversMissingShares() throws ReconstructionException {
        Share[] shared = algorithm.share(data);
        List<Share> shuffled = Arrays.asList(shared.clone());
        for (int i = 0; i <= n - k; i++) {
            Collections.shuffle(shuffled);
            Share[] dropped = shuffled.subList(i, n).toArray(new Share[0]);
            assertThat(dropped.length).isEqualTo(n - i);
            Share[] recovered = algorithm.recover(dropped);
            assertThat(recovered.length).isEqualTo(i);
            for (Share recov : recovered) {
                assertThat(recov).isEqualsToByComparingFields(shared[recov.getId() - 1]);
                assertThat(recov.getYValues()).isEqualTo(shared[recov.getId() - 1].getYValues());
            }
        }
    }

    @Test
    public void itWorksWithRecoveredShares() throws ReconstructionException {
        Share[] shares = algorithm.share(data);
        for (int i = 0; i <= n - k; i++) {
            Share[] cropped = Arrays.copyOfRange(shares, i, i+k);
            for (int j = 0; j < k; j++) {
                Share[] recovered = algorithm.recover(cropped);
                Share[] dropped = cropped;
                for (int d = 0; (d < n - k) && (d < k); d++) {
                    dropped = TestHelper.dropElementAt(dropped, 0);
                }
                Share[] combined = Stream.concat(Stream.of(recovered), Stream.of(dropped)).toArray(Share[]::new);
                assertThat(algorithm.reconstruct(combined)).isEqualTo(data);
            }
        }
    }
}
