package at.archistar.crypto.random;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

/**
 * This class tests and compares the performance of the different secure
 * RandomNumberGenerators.
 */
@RunWith(value = Parameterized.class)
public class RNGPerformanceTest {

    private final RandomSource rng;

    public RNGPerformanceTest(RandomSource rng) {
        this.rng = rng;
    }

    @Parameters
    public static Collection<Object[]> data() throws GeneralSecurityException {
        
        System.err.println("All operations are performed upon 500 pieces of 1MB share.");
        
        Object[][] data = new Object[][]{
            {new FakeRandomSource()},
            {new StreamPRNG(StreamPRNG.SALSA20)},
            {new StreamPRNG(StreamPRNG.HC128)},
            {new CTRPRNG()},
            {new JavaSecureRandom()},
            {new BCDigestRandomSource()},
        };

        return Arrays.asList(data);
    }

    @Test
    public void testPerformanceArray() {
        byte[] toBeFilled = new byte[1024 * 1024];

        long start = System.currentTimeMillis();
        for (int i = 0; i < 500; i++) {
            rng.fillBytes(toBeFilled);
        }
        long end = System.currentTimeMillis();

        System.out.format("%40s(as byte) %10dms\n", rng, end - start);
    }
    
    @Test
    public void testPerformanceArrayInt() {
        int[] toBeFilled = new int[1024 * 1024];

        long start = System.currentTimeMillis();
        for (int i = 0; i < 500; i++) {
            rng.fillBytesAsInts(toBeFilled);
        }
        long end = System.currentTimeMillis();

        System.out.format("%40s(as int)  %10dms\n", rng, end - start);
    }
}
