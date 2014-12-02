package at.archistar.crypto;

import at.archistar.TestHelper;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.random.FakeRandomSource;
import at.archistar.crypto.random.RandomSource;
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
public class EnginePerformanceTest {

    private final byte[][][] input;
    private final CryptoEngine engine;
    
    private static final int size = TestHelper.REDUCED_TEST_SIZE;
    
    @Parameters
    public static Collection<Object[]> data() throws WeakSecurityException, NoSuchAlgorithmException {
        
        System.err.println("Data-Size per Test: " + size/1024/1024 + "MByte");

        byte[][][] secrets = new byte[4][][];
        secrets[0] = TestHelper.createArray(size, 4 * 1024);       // typical file system block size
        secrets[1] = TestHelper.createArray(size, 128 * 1024);     // documents
        secrets[2] = TestHelper.createArray(size, 512 * 1024);     // documents, pictures (jpegs)
        secrets[3] = TestHelper.createArray(size, 4096 * 1024);    // audio, high-quality pictures

        RandomSource rng = new FakeRandomSource();
        
        Object[][] data = new Object[][]{
           {secrets, new RabinBenOrEngine(4, 3, rng)},
           {secrets, new RabinBenOrEngine(7, 3, rng)},
        };

        return Arrays.asList(data);
    }

    public EnginePerformanceTest(byte[][][] input, CryptoEngine engine) {
        this.input = input;
        this.engine = engine;
    }

    @Test
    public void testPerformance() throws Exception {

        for (int i = 0; i < input.length; i++) {
            double sumShare = 0;
            double sumCombine = 0;

            for (byte[] data : this.input[i]) {
                /* test construction */
                long beforeShare = System.currentTimeMillis();
                Share[] shares = engine.share(data);
                long betweenOperations = System.currentTimeMillis();
                byte[] reconstructed = engine.reconstruct(shares);
                long afterAll = System.currentTimeMillis();

                sumShare += (betweenOperations - beforeShare);
                sumCombine += (afterAll - betweenOperations);

                /* test that the reconstructed stuff is the same as the original one */
                assertThat(reconstructed).isEqualTo(data);
            }
            System.err.format("Performance(%dkB file size) of %s: share: %.3fkByte/sec, combine: %.2fkByte/sec\n", this.input[i][0].length/1024, this.engine, (size / 1024) / (sumShare / 1000.0), (size / 1024) / (sumCombine / 1000.0));
        }
    }
}
