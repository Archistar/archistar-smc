package at.archistar.crypto;

import java.security.GeneralSecurityException;

import org.junit.Test;

import at.archistar.crypto.KrawczykCSS;
import at.archistar.crypto.SecretSharing;
import at.archistar.crypto.WeakSecurityException;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.random.FakeRandomSource;
import static org.fest.assertions.api.Assertions.*;

/**
 * - * @author Andreas Happe <andreashappe@snikt.net>
 */
public class TestKrawczykCSS {

    @Test
    public void simpleRoundTest() throws WeakSecurityException, GeneralSecurityException {
        byte data[] = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

        SecretSharing algorithm = new KrawczykCSS(8, 5, new FakeRandomSource());

        Share shares[] = algorithm.share(data);
        assertThat(shares.length).isEqualTo(8);

        byte reconstructedData[] = algorithm.reconstruct(shares);
        assertThat(reconstructedData).isEqualTo(data);
    }
}
