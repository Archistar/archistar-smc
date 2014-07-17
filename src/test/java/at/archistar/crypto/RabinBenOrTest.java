package at.archistar.crypto;

import static org.fest.assertions.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.Collections;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import at.archistar.crypto.data.Share;
import at.archistar.crypto.exceptions.ReconstructionException;

/**
 * Tests for {@link RabinBenOrRSS}
 * @author Elias Frantar
 * @version 2014-7-17
 */
public class RabinBenOrTest {
	byte data[] = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
	private SecretSharing algorithm;
	
	/* setup and tear-down */
	@Before
	public void setup() {
		algorithm = new RabinBenOrRSS(new ShamirPSS(8, 5));
	}
	@After
	public void tearDown() {
		algorithm = null;
	}

	/* tests */
	
    @Test
    public void simpleRoundTest() throws ReconstructionException {
        Share shares[] = algorithm.share(data);
        assertThat(shares.length).isEqualTo(8);

        byte reconstructedData[] = algorithm.reconstruct(shares);
        assertThat(reconstructedData).isEqualTo(data);
    }
    
    @Test
    public void notAllSharesTest() throws ReconstructionException {
        Share shares[] = algorithm.share(data);
        Share shares1[] = Arrays.copyOfRange(shares, 0, 6);

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
    
    @Test(expected=ReconstructionException.class)
    public void notEnoughSharesTest() throws ReconstructionException {
        Share shares[] = algorithm.share(data);
        Share[] shares1 = Arrays.copyOfRange(shares, 0, 2);

        @SuppressWarnings("unused")
		byte reconstructedData[] = algorithm.reconstruct(shares1);
    }
}