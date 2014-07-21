package at.archistar.crypto;

import static org.fest.assertions.api.Assertions.*;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Collections;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import at.archistar.crypto.RabinIDS;
import at.archistar.crypto.SecretSharing;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.exceptions.WeakSecurityException;

/**
 * Tests for {@link RabinBenOrRSS}
 * 
 * @author Elias Frantar <i>(added additional test-cases)</i>
 * @author Andreas Happe <andreashappe@snikt.net>
 * @version 2014-7-21
 */
public class TestRabinIDS {
	byte data[] = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
	private SecretSharing algorithm;
	
	/* setup and tear-down */
	@Before
	public void setup() {
		algorithm = new RabinIDS(8, 5);
	}
	@After
	public void tearDown() {
		algorithm = null;
	}

	/* tests */
	
	/* should succeed reconstructing */
    @Test
    public void simpleRoundTest() throws WeakSecurityException, GeneralSecurityException {
        Share shares[] = algorithm.share(data);
        assertThat(shares.length).isEqualTo(8);

        byte reconstructedData[] = algorithm.reconstruct(shares);
        assertThat(reconstructedData).isEqualTo(data);
    }
    
    @Test
    public void notAllSharesTest() throws WeakSecurityException, GeneralSecurityException {
        Share shares[] = algorithm.share(data);
        Share shares1[] = Arrays.copyOfRange(shares, 0, 6);

        byte reconstructedData[] = algorithm.reconstruct(shares1);
        assertThat(reconstructedData).isEqualTo(data);
    }
    @Test
    public void shuffledSharesTest() throws WeakSecurityException, GeneralSecurityException {
        Share shares[] = algorithm.share(data);
        Collections.shuffle(Arrays.asList(shares));
        
        byte reconstructedData[] = algorithm.reconstruct(shares);
        assertThat(reconstructedData).isEqualTo(data);
    }
}
