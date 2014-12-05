package at.archistar.crypto.decode;

import at.archistar.crypto.data.Share;
import at.archistar.crypto.secretsharing.ReconstructionException;
import at.archistar.crypto.secretsharing.WeakSecurityException;
import at.archistar.crypto.math.GFFactory;
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
public class PerformanceTest {
    
    private final byte[][]input;
    private final SecretSharing algorithm;
    private final String name;
    
    private static final GFFactory gf256factory = new GF256Factory();
    private static final GFFactory bcgffactory = new BCGFFactory();
    private static final GFFactory gf257factory = new GF257Factory();
    
    private static final int size = 1024;
    
    private static byte[][] createArray(int testSize) {
        byte[][] result = new byte[testSize][size];

        for (int i = 0; i < testSize; i++) {
            for (int j = 0; j < size; j++) {
                result[i][j] = (byte)i;
            }
        }
        return result;
    }
    
    @Parameters
    public static Collection<Object[]> data() throws WeakSecurityException, NoSuchAlgorithmException {
        
        byte[][] secrets256 = createArray(4 * 1024);

        final int n = 4;
        final int k = 3;

        Object[][] data = new Object[][]{
           {"Rabin/Erasure mit GF256", secrets256, new RabinIDS(n, k, new ErasureDecoderFactory(gf256factory), gf256factory.createHelper())},
           {"Rabin/Erasure mit BCGF256", secrets256, new RabinIDS(n, k, new ErasureDecoderFactory(bcgffactory), bcgffactory.createHelper())},
           {"Rabin/Erasure mit GF257", secrets256, new RabinIDS(n, k, new ErasureDecoderFactory(gf257factory), gf257factory.createHelper())},
           {"Rabin/BW mit GF256", secrets256, new RabinIDS(n, k, new BerlekampWelchDecoderFactory(gf256factory), gf256factory.createHelper())},
           {"Rabin/BW mit BCGF256", secrets256, new RabinIDS(n, k, new BerlekampWelchDecoderFactory(bcgffactory), bcgffactory.createHelper())},
           {"Rabin/BW mit GF257", secrets256, new RabinIDS(n, k, new BerlekampWelchDecoderFactory(gf257factory), gf257factory.createHelper())}
        };
        return Arrays.asList(data);
    }
    
    public PerformanceTest(String name, byte[][] input, SecretSharing algorithm) {
        this.input = input;
        this.algorithm = algorithm;
        this.name = name;
    }

    @Test
    public void TestThroughRabinIDS() throws ReconstructionException {
        double sumShare = 0;
        double sumCombine = 0;

        double fullSize = 0;
        
        for (byte[] data : this.input) {
            fullSize += data.length;
            
            /* test construction */
            long beforeShare = System.currentTimeMillis();
            Share[] shares = algorithm.share(data);
            
            long betweenOperations = System.currentTimeMillis();
            byte[] reconstructed = algorithm.reconstruct(shares);
            long afterAll = System.currentTimeMillis();

            sumShare += (betweenOperations - beforeShare);
            sumCombine += (afterAll - betweenOperations);
            
            assert(reconstructed.length == data.length);

            /* test that the reconstructed stuff is the same as the original one */
            assertThat(reconstructed).isEqualTo(data);
        }
        fullSize /= 1024;
        System.err.format("%33s %4.0fkB %12.1f %12.1f\n", name, fullSize, fullSize / (sumShare / 1000.0), fullSize / (sumCombine / 1000.0));
    }
}
