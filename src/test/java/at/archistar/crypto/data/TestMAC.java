package at.archistar.crypto.data;

import java.security.GeneralSecurityException;

import org.junit.Test;

import at.archistar.crypto.SecretSharing;
import at.archistar.crypto.ShamirPSS;
import at.archistar.crypto.WeakSecurityException;
import at.archistar.crypto.data.InformationChecking;
import at.archistar.crypto.data.MacHelper;
import at.archistar.crypto.data.MacSha512;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.random.FakeRandomSource;
import static org.fest.assertions.api.Assertions.*;

/**
 * - * @author Andreas Happe <andreashappe@snikt.net>
 */
public class TestMAC {

    @Test
    public void testMAC() throws WeakSecurityException, GeneralSecurityException {
        byte data[] = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

        SecretSharing algorithm = new ShamirPSS(8, 5, new FakeRandomSource());
        Share shares[] = algorithm.share(data);

        MacHelper macHelper = new MacSha512(new FakeRandomSource());

        InformationChecking maccer = new InformationChecking(macHelper);

        maccer.addMacs(shares, "HMacSHA512");
        assertThat(maccer.checkMacs("HMacSHA512", shares)).isEqualTo(true);
    }
}
