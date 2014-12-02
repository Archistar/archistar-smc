package at.archistar.crypto.decode;

import at.archistar.crypto.TestHelper;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.mac.ShareMacHelper;
import at.archistar.crypto.math.GFFactory;
import at.archistar.crypto.math.gf256.GF256Factory;
import at.archistar.crypto.secretsharing.RabinIDS;
import at.archistar.crypto.secretsharing.BaseSecretSharing;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;

import static org.fest.assertions.api.Assertions.*;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

/**
 * Tests the performance of the different decoders.
 * 
 * TODO: need to make this a real decoder test! for now we're just using
 * the same crypto setup to detect differences between decoders.
 */
@RunWith(value = Parameterized.class)
public class PerformanceTest {

    private final byte[][][] input;
    private final BaseSecretSharing algorithm;
    private static final int size = TestHelper.REDUCED_TEST_SIZE;
    
    private static final GFFactory gffactory  = new GF256Factory();
    
    @Parameters
    public static Collection<Object[]> data() throws WeakSecurityException, NoSuchAlgorithmException {
        
        System.err.println("Data-Size per Test: " + size/1024/1024 + "MByte");

        byte[][][] secrets = new byte[4][][];
        secrets[0] = TestHelper.createArray(size, 4 * 1024);       // typical file system block size
        secrets[1] = TestHelper.createArray(size, 128 * 1024);     // documents
        secrets[2] = TestHelper.createArray(size, 512 * 1024);     // documents, pictures (jpegs)
        secrets[3] = TestHelper.createArray(size, 4096 * 1024);    // audio, high-quality pictures

        ShareMacHelper mac = new ShareMacHelper("HMacSHA256");
                
        Object[][] data = new Object[][]{
           {secrets, new RabinIDS(5, 3, new ErasureDecoderFactory(gffactory))},
           {secrets, new RabinIDS(5, 3, new BerlekampWelchDecoderFactory(gffactory))}
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
            double sum = 0;

            for (byte[] data : this.input[i]) {
                /* test construction */
                Share[] shares = algorithm.share(data);
                long beforeDecode = System.currentTimeMillis();
                byte[] reconstructed = algorithm.reconstruct(shares);
                long afterDecode = System.currentTimeMillis();

                sum += (afterDecode - beforeDecode);

                /* test that the reconstructed stuff is the same as the original one */
                assertThat(reconstructed).isEqualTo(data);
            }
            System.err.format("Pseudo-Decode-Performance(%dkB file size) of %s: combine/decode: %.2fkByte/sec\n", this.input[i][0].length/1024, this.algorithm, (size / 1024) / (sum / 1000.0));
        }
    }
}
