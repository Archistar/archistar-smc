package at.archistar.crypto;

import java.security.GeneralSecurityException;

import org.junit.Test;

import static org.fest.assertions.api.Assertions.*;
import at.archistar.crypto.KrawczykCSS;
import at.archistar.crypto.RabinBenOrRSS;
import at.archistar.crypto.SecretSharing;
import at.archistar.crypto.WeakSecurityException;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.random.FakeRandomSource;
import at.archistar.crypto.random.RandomSource;

/**
 * - * @author Andreas Happe <andreashappe@snikt.net>
 */
public class TestRabinBenOrRSS {

    @Test
    public void simpleRoundTest() throws WeakSecurityException, GeneralSecurityException {
        byte data[] = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        RandomSource rng = new FakeRandomSource();

        SecretSharing helperAlgorithm = new KrawczykCSS(8, 5, rng);
        SecretSharing algorithm = new RabinBenOrRSS(8, 5, rng, helperAlgorithm);

        Share shares[] = algorithm.share(data);
        assertThat(shares.length).isEqualTo(8);

        byte reconstructedData[] = algorithm.reconstruct(shares);
        assertThat(reconstructedData).isEqualTo(data);
    }
}
