package at.archistar.crypto;

import static org.fest.assertions.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.Collections;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import at.archistar.crypto.data.Share;
import at.archistar.crypto.exceptions.ImpossibleException;
import at.archistar.crypto.exceptions.ReconstructionException;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.random.FakeRandomSource;

/**
 * Tests for {@link CevallosUSRSS}
 * @author Elias Frantar
 * @version 2014-7-29
 */
public class TestCevallosUSRSS {
    byte data[] = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private SecretSharing algorithm;
    
    @Before
    public void setup() throws WeakSecurityException {
        algorithm = new CevallosUSRSS(8, 4, new FakeRandomSource());
    }
    @After
    public void tearDown() {
        algorithm = null;
    }
    
    /* expected successful encryption */
    @Test
    public void simpleRoundTest() throws ReconstructionException {
        Share shares[] = algorithm.share(data);

        byte reconstructedData[] = algorithm.reconstruct(shares);
        assertThat(reconstructedData).isEqualTo(data);
    }
    
    @Test
    public void tGoodRangeLowerBoundGoodTest() throws WeakSecurityException{
    	int n = 11;
    	int t = 4;
        new CevallosUSRSS(n, t + 1, new FakeRandomSource()); // very close above the lower bound n/3
    }
    
    @Test(expected=ImpossibleException.class)
    public void tGoodRangeLowerBoundFailTest() throws WeakSecurityException{
    	int n = 11;
    	int t = 3;
        new CevallosUSRSS(n, t + 1, new FakeRandomSource()); // very close below the lower bound n/3
    }
    
    @Test
    public void tRangeUpperBoundLimitGoodTest() throws WeakSecurityException{
    	int n = 11;
    	int t = 5;
        new CevallosUSRSS(n, t + 1, new FakeRandomSource()); // here t is close to the upper bound but still in the good range
    }
    
    @Test(expected=ImpossibleException.class)
    public void tGoodRangeUpperBoundLimitFailTest() throws WeakSecurityException{
    	int n = 10;
    	int t = 5;
        new CevallosUSRSS(n, t + 1, new FakeRandomSource()); // here the t is over the upper bound
    }
    
    @Test
    public void notAllSharesTest() throws ReconstructionException {
        Share shares[] = algorithm.share(data);
        Share[] shares1 = Arrays.copyOfRange(shares, 1, 6);

        byte reconstructedData[] = algorithm.reconstruct(shares1);
        assertThat(reconstructedData).isEqualTo(data);
    }
    @Test
    public void shuffledSharesTest() throws ReconstructionException {
        Share shares[] = algorithm.share(data);
        Collections.shuffle(Arrays.asList(shares));

        byte reconstructedData[] = algorithm.reconstruct(shares);
        assertThat(reconstructedData).isEqualTo(data);
    }
    
    /* expected failing decryption */
    @Test(expected=ReconstructionException.class)
    public void notEnoughSharesTest() throws ReconstructionException {
        Share shares[] = algorithm.share(data);
        Share[] shares1 = Arrays.copyOfRange(shares, 0, 2);
        
        @SuppressWarnings("unused")
        byte reconstructedData[] = algorithm.reconstruct(shares1);
    }

}
