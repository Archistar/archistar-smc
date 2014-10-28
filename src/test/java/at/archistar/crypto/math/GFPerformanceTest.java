package at.archistar.crypto.math;

import at.archistar.crypto.TestHelper;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.decode.BerlekampWelchDecoderFactory;
import at.archistar.crypto.decode.ErasureDecoderFactory;
import at.archistar.crypto.exceptions.ReconstructionException;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.math.bc.BCGFFactory;
import at.archistar.crypto.math.gf256.GF256Factory;
import at.archistar.crypto.math.gf257.GF257Factory;
import at.archistar.crypto.secretsharing.RabinIDS;
import at.archistar.crypto.secretsharing.SecretSharing;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;
import static org.fest.assertions.api.Assertions.*;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

/**
 * @author andy
 */
@RunWith(value = Parameterized.class)
public class GFPerformanceTest {
    
    private final byte[][]input;
    private final SecretSharing algorithm;
    private final String name;
    
    private static final GFFactory gf256factory = new GF256Factory();
    private static final GFFactory bcgffactory = new BCGFFactory();
    private static final GFFactory gf257factory = new GF257Factory();
    
    private static final int size = TestHelper.REDUCED_TEST_SIZE;
    
    @Parameters
    public static Collection<Object[]> data() throws WeakSecurityException, NoSuchAlgorithmException {
        
        byte[][] secrets = TestHelper.createArray(size, 4*1024);

        final int n = 4;
        final int k = 3;

        Object[][] data = new Object[][]{
           {"Erasure mit GF256", secrets, new RabinIDS(n, k, new ErasureDecoderFactory(gf256factory), gf256factory.createHelper())},
           {"Erasure mit BCGF256", secrets, new RabinIDS(n, k, new ErasureDecoderFactory(bcgffactory), bcgffactory.createHelper())},
           {"Erasure mit GF257", secrets, new RabinIDS(n, k, new ErasureDecoderFactory(gf257factory), gf257factory.createHelper())},
           {"BW mit GF256", secrets, new RabinIDS(n, k, new BerlekampWelchDecoderFactory(gf256factory), gf256factory.createHelper())},
           {"BW mit BCGF256", secrets, new RabinIDS(n, k, new BerlekampWelchDecoderFactory(bcgffactory), bcgffactory.createHelper())},
           //{"BW mit GF257", secrets, new RabinIDS(n, k, new BerlekampWelchDecoderFactory(gf257factory), gf257factory.createHelper())}
        };
        return Arrays.asList(data);
    }
    
    public GFPerformanceTest(String name, byte[][] input, SecretSharing algorithm) {
        this.input = input;
        this.algorithm = algorithm;
        this.name = name;
    }

    @Test
    public void TestThroughRabinIDS() throws ReconstructionException {
        double sumShare = 0;
        double sumCombine = 0;

        for (byte[] data : this.input) {
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
        System.err.format("Performance(%dkB file size) of %s: share: %.3fkByte/sec, combine: %.2fkByte/sec\n", this.input[0].length / 1024, this.name, (size / 1024) / (sumShare / 1000.0), (size / 1024) / (sumCombine / 1000.0));
    }
}
