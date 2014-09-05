package at.archistar.crypto;

import at.archistar.crypto.data.Share;
import at.archistar.crypto.exceptions.ReconstructionException;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.random.FakeRandomSource;
import at.archistar.crypto.random.RandomSource;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import static org.fest.assertions.api.Assertions.assertThat;

import static org.junit.Assert.fail;
import org.junit.Test;

/**
 * Tests for {@link CevallosEngine}
 */
public class TestCevallosEngine {
    private static final byte data[] = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private static final RandomSource rng = new FakeRandomSource();
    
    /** A simple working share/reconstruct round over data.
     * 
     * @throws ReconstructionException reconstruction did not work
     * @throws WeakSecurityException should not happen due to fixed parameters
     * @throws NoSuchAlgorithmException should not happen due to fixed algorithms
      */
    @Test
    public void simpleShareReconstructRound() throws ReconstructionException, WeakSecurityException, NoSuchAlgorithmException {
        CryptoEngine algorithm = new CevallosEngine(8, 4, rng);
        Share shares[] = algorithm.share(data);
        byte reconstructedData[] = algorithm.reconstruct(shares);
        assertThat(reconstructedData).isEqualTo(data);
    }

    /** Create a new CryptoEngine if t >= n/3 (lower) and upper bound
     * 
     * @throws WeakSecurityException should not happen due to fixed parameters
     * @throws NoSuchAlgorithmException should not happen due to fixed algorithms
     */
    @Test
    public void withinLowerBounds() throws WeakSecurityException, NoSuchAlgorithmException{
        
        /* TODO: loop over n to test more cases (: */
        
    	int n = 12;
    	int t = n/3;
        CryptoEngine engine = new CevallosEngine(n, t+1, rng);
        assertThat(engine).isNotNull();
    }

    /** Fail if lower than bound n/3
     * 
     * @throws WeakSecurityException happen as the lower bound is reached
     * @throws NoSuchAlgorithmException should not happen due to fixed algorithms
     */
    @Test(expected=WeakSecurityException.class)
    public void failOutsideofLowerBound() throws WeakSecurityException, NoSuchAlgorithmException{
    	int n = 11;
    	int t = 3;
        CryptoEngine engine = new CevallosEngine(n, t+1, rng);
        fail();
    }

    /** Create a new CryptoEngine if t >= n/3 (lower) and upper bound
     * 
     * @throws WeakSecurityException should not happen due to fixed parameters
     * @throws NoSuchAlgorithmException should not happen due to fixed algorithms
     */
    @Test
    public void withinUpperBound() throws WeakSecurityException, NoSuchAlgorithmException{
    	int n = 11;
    	int t = 5;
        CryptoEngine engine = new CevallosEngine(n, t, rng);
        assertThat(engine).isNotNull();
    }

    /** Fail if t is higher than the upper bound
     * 
     * TODO: do we really want to fail when this happens?
     * 
     * @throws WeakSecurityException happen as the upper bound was reached
     * @throws NoSuchAlgorithmException should not happen due to fixed algorithms
     */
    @Test(expected=WeakSecurityException.class)
    public void tGoodRangeUpperBoundLimitFailTest() throws WeakSecurityException, NoSuchAlgorithmException{
    	int n = 10;
    	int t = 5;
        CryptoEngine engine = new CevallosEngine(n, t + 1, rng);
        fail();
    }

    /** it should reconstruct if the number of shares > k
     * 
     * @throws ReconstructionException if this is thrown the test really fails
     * @throws WeakSecurityException happen as the upper bound was reached
     * @throws NoSuchAlgorithmException should not happen due to fixed algorithms
     */
    @Test
    public void reconstructPartialShares() throws ReconstructionException, WeakSecurityException, NoSuchAlgorithmException {
        int n = 8;
        int k = 4;
        
        CryptoEngine algorithm = new CevallosEngine(n, k, rng);
        Share shares[] = algorithm.share(data);
        for(int i = k; i < n; i++) {
            Share[] shares1 = Arrays.copyOfRange(shares, 0, i);
            byte reconstructedData[] = algorithm.reconstruct(shares1);
            assertThat(reconstructedData).isEqualTo(data);
        }
    }
    
    /** it should reconstruct if shares were shuffled
     * 
     * @throws ReconstructionException if this is thrown the test really fails
     * @throws WeakSecurityException happen as the upper bound was reached
     * @throws NoSuchAlgorithmException should not happen due to fixed algorithms
     */
    @Test
    public void shuffleSharesBeforeReconstruct() throws ReconstructionException, WeakSecurityException, NoSuchAlgorithmException {
        CryptoEngine algorithm = new CevallosEngine(8, 4, rng);
        Share shares[] = algorithm.share(data);
        Collections.shuffle(Arrays.asList(shares));
        byte reconstructedData[] = algorithm.reconstruct(shares);
        assertThat(reconstructedData).isEqualTo(data);
    }
    
    /** it should fail if the number of shares <= k
     * 
     * @throws WeakSecurityException happen as the upper bound was reached
     * @throws NoSuchAlgorithmException should not happen due to fixed algorithms
     */
    public void failIfThereAintEnoughShares() throws WeakSecurityException, NoSuchAlgorithmException {
        int n=8;
        int k=4;
        
        CryptoEngine algorithm = new CevallosEngine(n, k, rng);
        Share shares[] = algorithm.share(data);
        
        for (int i = 0; i < k; i++) {
            Share[] shares1 = Arrays.copyOfRange(shares, 0, k);
            try {
                algorithm.reconstruct(shares1);
                fail("could reconstruct even if there were too few shares! (k=" + k + ")");
            } catch(ReconstructionException ex) {
                // actually the good case!
            }
        }
    }
}
