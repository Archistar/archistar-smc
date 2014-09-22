package at.archistar.crypto.mac;

import at.archistar.crypto.informationchecking.CevallosUSRSS;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import static org.fest.assertions.api.Assertions.assertThat;
import org.junit.Test;

public class BCShortenedMacTest {

    @Test
    public void testHashVerifyCycle() throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] data = new byte[1024];
        byte[] key = new byte[128];
        
        MacHelper mac = new BCShortenedMacHelper(new BCPoly1305MacHelper(), CevallosUSRSS.computeTagLength(data.length, 1, CevallosUSRSS.E));
        
        byte[] hash = mac.computeMAC(data, key);
        
        assertThat(mac.verifyMAC(data, hash, key)).isEqualTo(true);
    }
}
