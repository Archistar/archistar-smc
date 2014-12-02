package at.archistar.crypto.secretsharing;

import at.archistar.TestHelper;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.decode.ErasureDecoderFactory;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.mac.ShareMacHelper;
import at.archistar.crypto.math.GF;
import at.archistar.crypto.math.GFFactory;
import at.archistar.crypto.math.gf256.GF256Factory;
import at.archistar.crypto.random.FakeRandomSource;
import at.archistar.crypto.random.RandomSource;
import at.archistar.crypto.symmetric.AESEncryptor;
import at.archistar.crypto.symmetric.AESGCMEncryptor;
import at.archistar.crypto.symmetric.ChaCha20Encryptor;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;

import static org.fest.assertions.api.Assertions.*;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

/**
 * Tests the performance of the different Secret-Sharing algorithms. 
 */
@RunWith(value = Parameterized.class)
public class PerformanceTest {

    private final byte[][][] input;
    private final BaseSecretSharing algorithm;
    
    @Parameters
    public static Collection<Object[]> data() throws WeakSecurityException, NoSuchAlgorithmException {
        
        System.err.println("Data-Size per Test: " + TestHelper.TEST_SIZE/1024/1024 + "MByte");

        byte[][][] secrets = new byte[4][][];
        secrets[0] = TestHelper.createArray(4 * 1024);       // typical file system block size
        secrets[1] = TestHelper.createArray(128 * 1024);     // documents
        secrets[2] = TestHelper.createArray(512 * 1024);     // documents, pictures (jpegs)
        secrets[3] = TestHelper.createArray(4096 * 1024);    // audio, high-quality pictures

        final int n = 4;
        final int k = 3;

        RandomSource rng = new FakeRandomSource();
        ShareMacHelper mac = new ShareMacHelper("HMacSHA256");
        
        GFFactory gffactory = new GF256Factory();
        DecoderFactory df = new ErasureDecoderFactory(gffactory);
        GF gf = gffactory.createHelper();
        
        Object[][] data = new Object[][]{
           {secrets, new ShamirPSS(n, k, rng, df, gf)},
           {secrets, new RabinIDS(n, k, df, gf)},
           {secrets, new KrawczykCSS(n, k, rng, new AESEncryptor(), df, gf)},
           {secrets, new KrawczykCSS(n, k, rng, new AESGCMEncryptor(), df, gf)},
           {secrets, new KrawczykCSS(n, k, rng, new ChaCha20Encryptor(), df, gf)}
        };

        return Arrays.asList(data);
    }

    public PerformanceTest(byte[][][] input, BaseSecretSharing algorithm) {
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
            System.err.format("Performance(%dkB file size) of %s: share: %.3fkByte/sec, combine: %.2fkByte/sec\n", this.input[i][0].length/1024, this.algorithm, (TestHelper.TEST_SIZE / 1024) / (sumShare / 1000.0), (TestHelper.TEST_SIZE / 1024) / (sumCombine / 1000.0));
        }
    }
}
