package at.archistar.crypto;
import static org.fest.assertions.api.Assertions.*;

import java.security.GeneralSecurityException;

import org.junit.Test;

import at.archistar.crypto.RabinIDS;
import at.archistar.crypto.SecretSharing;
import at.archistar.crypto.WeakSecurityException;
import at.archistar.crypto.data.Share;

/**
- * @author Andreas Happe <andreashappe@snikt.net>
*/
public class TestRabinIDS {

	@Test
	public void simpleRoundTest() throws WeakSecurityException, GeneralSecurityException {
		byte data[] = new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
		
		SecretSharing algorithm = new RabinIDS(8, 5);
		
		Share shares[] = algorithm.share(data);
		assertThat(shares.length).isEqualTo(8);
		
		byte reconstructedData[] = algorithm.reconstruct(shares);
		assertThat(reconstructedData).isEqualTo(data);
	}

}