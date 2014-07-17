package at.archistar.crypto;

import static org.fest.assertions.api.Assertions.*;

import java.util.Arrays;
import java.util.Collections;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import at.archistar.crypto.ShamirPSS;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.exceptions.ReconstructionException;

/**
 * Tests for {@link ShamirPSSTest}
 * @author Elias Frantar <i>(added additional test-cases)</i>
 * @author Andreas Happe <andreashappe@snikt.net>
 * @version 2014-7-17
 */
public class ShamirPSSTest {
    byte data[] = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
	private SecretSharing algorithm;
	
	/* setup and tear-down */
	@Before
	public void setup() {
		algorithm = new ShamirPSS(8, 3);
	}
	@After
	public void tearDown() {
		algorithm = null;
	}
	
	/* tests */
	
    @Test
    public void simpleRoundTest() throws ReconstructionException {
        Share shares[] = algorithm.share(data);

        byte reconstructedData[] = algorithm.reconstruct(shares);
        assertThat(reconstructedData).isEqualTo(data);
    }
    
    @Test
    public void notAllSharesTest() throws ReconstructionException {
        Share shares[] = algorithm.share(data);
        Share[] shares1 = Arrays.copyOfRange(shares, 1, 4);

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
    
    @Test
    public void notEnoughValidSharesTest() throws ReconstructionException {
        Share shares[] = algorithm.share(data);
        shares[0].setX((byte)12);
        Share[] shares1 = Arrays.copyOfRange(shares, 0, 3);

        byte reconstructedData[] = algorithm.reconstruct(shares1);
        assertThat(reconstructedData).isNotEqualTo(data);
    } 
    @Test
    public void withFaultyShare() throws ReconstructionException {
        Share shares[] = algorithm.share(data);
        shares[0].setX((byte)17);

        byte reconstructedData[] = algorithm.reconstruct(shares);
        assertThat(reconstructedData).isNotEqualTo(data);
    }
}