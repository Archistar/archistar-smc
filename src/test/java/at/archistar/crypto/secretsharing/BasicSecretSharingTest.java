package at.archistar.crypto.secretsharing;

import at.archistar.crypto.data.Share;
import at.archistar.crypto.exceptions.ReconstructionException;
import java.util.Arrays;
import java.util.Collections;
import static org.fest.assertions.api.Assertions.assertThat;
import static org.fest.assertions.api.Assertions.fail;
import org.junit.Test;

/**
 * all secret-sharing algorithms should at least provide this functionality
 */
public abstract class BasicSecretSharingTest {
    
    protected SecretSharing algorithm;
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
        
        for (int i=k; i < n; i++) {
            Share[] shares1 = Arrays.copyOf(shares, i);
            byte reconstructedData[] = algorithm.reconstruct(shares1);
            assertThat(reconstructedData).isEqualTo(data);
        }
    }

    @Test
    public void itReconstrutsShuffledShares() throws ReconstructionException {
        Share shares[] = algorithm.share(data);
        Collections.shuffle(Arrays.asList(shares));
        byte reconstructedData[] = algorithm.reconstruct(shares);
        assertThat(reconstructedData).isEqualTo(data);
    }

    @Test
    public void itFailsWhenThereAreTooFewShares() {
        Share shares[] = algorithm.share(data);
        
        for (int i=0; i < k; i++) {
            Share[] shares1 = Arrays.copyOf(shares, i);

            try {
                algorithm.reconstruct(shares1);
                fail("too few shares to reconstruct, what was returned?");
            } catch(ReconstructionException ex) {
                // this is the good (expected) case
            }
        }
    }
}
