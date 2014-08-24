package at.archistar.crypto;

import at.archistar.crypto.data.Share;
import at.archistar.crypto.decode.BerlekampWelchDecoderFactory;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.mac.BCMacHelper;
import at.archistar.crypto.mac.BCPoly1305MacHelper;
import at.archistar.crypto.mac.BCShortenedMacHelper;
import at.archistar.crypto.mac.ShareMacHelper;
import at.archistar.crypto.mac.ShortenedMacHelper;
import at.archistar.crypto.random.FakeRandomSource;
import at.archistar.crypto.random.RandomSource;
import at.archistar.crypto.symmetric.AESEncryptor;
import at.archistar.crypto.symmetric.AESGCMEncryptor;
import at.archistar.crypto.symmetric.ChaCha20Encryptor;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.macs.SipHash;

import static org.fest.assertions.api.Assertions.*;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

/**
 * Tests and compares the performance of the different Secret-Sharing algorithms. 
 * (does use {@link ErasureDecoder} for reconstruction)
 * 
 * @author Elias Frantar <i>(added documentation)</i>
 * @author Andreas Happe <andreashappe@snikt.net>
 * @version 2014-7-28
 */
@RunWith(value = Parameterized.class)
public class PerformanceTest {

    private final byte[][][] input;
    private final SecretSharing algorithm;
    private static final int size = 20 * 1024 * 1024;
    
    /**
     * Creates a byte[] of the given size, with all values set to 42.
     * @param elementSize the size of the array
     * @return an array of the given size
     */
    private static byte[][] createArray(int elementSize) {
        byte[][] result = new byte[size / elementSize][elementSize];

        for (int i = 0; i < size / elementSize; i++) {
            for (int j = 0; j < elementSize; j++) {
                result[i][j] = 42;
            }
        }

        return result;
    }

    @Parameters
    public static Collection<Object[]> data() throws WeakSecurityException, NoSuchAlgorithmException {
        
        System.err.println("Data-Size per Test: " + size/1024/1024 + "MByte");

        byte[][][] secrets = new byte[4][][];
        secrets[0] = createArray(4 * 1024);       // typical file system block size
        secrets[1] = createArray(128 * 1024);     // documents
        secrets[2] = createArray(512 * 1024);     // documents, pictures (jpegs)
        secrets[3] = createArray(4096 * 1024);    // audio, high-quality pictures

        final int n = 4;
        final int k = 3;

        RandomSource rng = new FakeRandomSource();
        ShareMacHelper mac = new ShareMacHelper("HMacSHA256");
        
        Object[][] data = new Object[][]{
           {secrets, new ShamirPSS(n, k, rng)},
           {secrets, new RabinIDS(n, k)},
           {secrets, new KrawczykCSS(n, k, rng, new AESEncryptor())},
           {secrets, new KrawczykCSS(n, k, rng, new AESGCMEncryptor())},
           {secrets, new KrawczykCSS(n, k, rng, new ChaCha20Encryptor())},
           {secrets, new RabinBenOrRSS(new KrawczykCSS(n, k, rng), mac, rng)},
           {secrets, new RabinBenOrRSS(new KrawczykCSS(n, k, rng, new ChaCha20Encryptor()), mac, rng)},
           {secrets, new RabinBenOrRSS(new KrawczykCSS(n, k, rng), new BCPoly1305MacHelper(), rng)},
           {secrets, new RabinBenOrRSS(new KrawczykCSS(n, k, rng, new ChaCha20Encryptor()), new BCPoly1305MacHelper(), rng)},
           {secrets, new CevallosUSRSS(5, 3, new BerlekampWelchDecoderFactory(), rng, new ShortenedMacHelper("HMacSHA256", 3, CevallosUSRSS.E))},
           {secrets, new CevallosUSRSS(5, 3, new BerlekampWelchDecoderFactory(), rng, new BCShortenedMacHelper(new BCPoly1305MacHelper(), 3, CevallosUSRSS.E))},
           {secrets, new CevallosUSRSS(5, 3, new BerlekampWelchDecoderFactory(), rng, new BCShortenedMacHelper(new BCMacHelper(new SipHash(2, 4), 16), 3, CevallosUSRSS.E))}
        };

        return Arrays.asList(data);
    }

    public PerformanceTest(byte[][][] input, SecretSharing algorithm) {
        this.input = input;
        this.algorithm = algorithm;
    }

    @Test
    public void testPerformance() throws Exception {

        for (int i = 0; i < input.length; i++) {
            double sumShare = 0;
            double sumCombine = 0;

            for (byte[] data : this.input[i]) {
                /* test construction */
                long beforeShare = System.currentTimeMillis();
                Share[] shares = algorithm.share(data);
                long betweenOperations = System.currentTimeMillis();
                byte[] reconstructed = algorithm.reconstruct(shares);
                long afterAll = System.currentTimeMillis();

                sumShare += (betweenOperations - beforeShare);
                sumCombine += (afterAll - betweenOperations);

                /* test that the reconstructed stuff is the same as the original one */
                assertThat(reconstructed).isEqualTo(data);
            }
            System.err.format("Performance(%dkB file size) of %s: share: %.3fkByte/sec, combine: %.2fkByte/sec\n", this.input[i][0].length/1024, this.algorithm, (size / 1024) / (sumShare / 1000.0), (size / 1024) / (sumCombine / 1000.0));
        }
    }
}
