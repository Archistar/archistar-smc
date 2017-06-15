package at.archistar.crypto;

import at.archistar.crypto.data.BrokenShare;
import at.archistar.crypto.data.ReconstructionResult;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.data.ShareFactory;
import at.archistar.crypto.random.FakeRandomSource;
import at.archistar.crypto.random.RandomSource;
import at.archistar.crypto.secretsharing.ReconstructionException;
import at.archistar.crypto.secretsharing.WeakSecurityException;
import org.junit.Test;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;

import static org.fest.assertions.api.Assertions.assertThat;

/**
 * @author florian
 */
public abstract class AbstractEngineTest {

    protected final static RandomSource rng = new FakeRandomSource();
    protected final byte data[] = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    protected final int n = 8;
    protected final int k = 5;
    protected CryptoEngine algorithm;

    /**
     * After a simple share+reconstruct step the reconstructed data should be
     * the same as the original data
     *
     * @throws WeakSecurityException   should not happen due to fixed setup
     * @throws ReconstructionException should not happen due to fixed setup
     */
    @Test
    public void simpleShareReconstructRound() throws ReconstructionException, WeakSecurityException {
        Share shares[] = algorithm.share(data);
        assertThat(shares.length).isEqualTo(n);
        ReconstructionResult reconstructedData = algorithm.reconstruct(shares);
        assertThat(reconstructedData.getData()).isEqualTo(data);
    }

    /**
     * Reconstruct should work as long as share count > k
     *
     * @throws WeakSecurityException   should not happen due to fixed setup
     * @throws ReconstructionException should not happen due to fixed setup
     */
    @Test
    public void reconstructWithSufficientSubSet() throws ReconstructionException, WeakSecurityException {
        Share shares[] = algorithm.share(data);

        for (int i = k + 1; i < n; i++) {
            Share shares1[] = Arrays.copyOfRange(shares, 0, i);
            ReconstructionResult reconstructedData = algorithm.reconstruct(shares1);
            assertThat(reconstructedData.getData()).isEqualTo(data);
        }
    }

    /**
     * Reconstruct should work with shuffled shares
     *
     * @throws WeakSecurityException   should not happen due to fixed setup
     * @throws ReconstructionException should not happen due to fixed setup
     */
    @Test
    public void reconstructShuffledShares() throws ReconstructionException, WeakSecurityException {
        Share shares[] = algorithm.share(data);
        Collections.shuffle(Arrays.asList(shares));

        ReconstructionResult reconstructedData = algorithm.reconstruct(shares);
        assertThat(reconstructedData.getData()).isEqualTo(data);
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
            ReconstructionResult result = algorithm.reconstruct(shares1);
            assertThat(result.isOkay()).isFalse();
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

    @Test
    public void serialization() throws IOException, ReconstructionException {
        Share[] shares = algorithm.share(data);
        Share[] deserialized = new Share[n];
        for (int i = 0; i < shares.length; i++) {
            Share s = shares[i];
            Share des = ShareFactory.deserialize(s.getSerializedData(), s.getMetaData());
            assertThat(des instanceof BrokenShare).isFalse();
            deserialized[i] = des;
        }
        ReconstructionResult result = algorithm.reconstruct(deserialized);
        assertThat(result.isOkay()).isTrue();
        assertThat(result.getData()).isEqualTo(data);
    }
}
