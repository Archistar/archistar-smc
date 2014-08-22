package at.archistar.crypto.random;

import at.archistar.crypto.exceptions.CryptoException;
import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

/**
 * This class tests and compares the performance of the different secure
 * RandomNumberGenerators.
 *
 * @author Elias Frantar
 * @version 2014-7-18
 */
@RunWith(value = Parameterized.class)
public class RNGPerformanceTest {

    private final RandomSource rng;

    public RNGPerformanceTest(RandomSource rng) {
        this.rng = rng;
    }

    @Parameters
    public static Collection<Object[]> data() throws CryptoException {
        Object[][] data = new Object[][]{
            {new FakeRandomSource()},
            {new StreamPRNG(StreamPRNG.SALSA20)},
            {new StreamPRNG(StreamPRNG.HC128)},
            {new CTRPRNG()},
            {new SHA1PRNG()},
            {new BCDigestRandomSource()}
        };

        return Arrays.asList(data);
    }

    @Test
    public void testPerformanceByte() {
        long start = System.currentTimeMillis();
        for (int i = 0; i < 1024 * 1024 * 500; i++) {
            rng.generateByte();
        }
        long end = System.currentTimeMillis();

        System.out.println(rng.toString() + ": 500MB in " + (end - start) + "ms");
    }

    @Test
    public void testPerformanceArray() {
        byte[] toBeFilled = new byte[1024 * 1024];

        long start = System.currentTimeMillis();
        for (int i = 0; i < 500; i++) {
            rng.fillBytes(toBeFilled);
        }
        long end = System.currentTimeMillis();

        System.out.println(rng.toString() + " (array): 500MB a 1 MB in " + (end - start) + "ms");
    }
}
