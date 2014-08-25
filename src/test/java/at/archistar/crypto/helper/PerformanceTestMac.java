package at.archistar.crypto.helper;

import at.archistar.crypto.data.ShamirShare;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.random.FakeRandomSource;
import at.archistar.crypto.random.RandomSource;
import at.archistar.helper.ShareMacHelper;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;

/**
 * Doing performance test on various mac algorithms.
 *
 * @author Gary Ye (ye.gary13@hotmail.com)
 */
@RunWith(value = Parameterized.class)
public class PerformanceTestMac {
    final static int size = 1 << 28;
    ShareMacHelper macHelper;
    String macAlgorithmName;
    Share hashData;

    @Parameterized.Parameters
    public static Collection<Object[]> data() throws NoSuchAlgorithmException {
        byte[] randomBytes = new byte[size];
        for (int i = 0; i < randomBytes.length; i++)
            randomBytes[i] = (byte) i;

        Object[][] data = new Object[][]{
                {new ShamirShare((byte)1, randomBytes), "HmacSHA256", new FakeRandomSource()}
        };
        return Arrays.asList(data);
    }

    public PerformanceTestMac(Share hashData, String macAlgorithmName, RandomSource rng) throws NoSuchAlgorithmException {
        this.hashData = hashData;
        this.macAlgorithmName = macAlgorithmName;
        this.macHelper = new ShareMacHelper(macAlgorithmName, rng);
    }

    @Test
    public void testPerformance() throws Exception {
        long computeTime, verifyTime;
        byte[] key = new byte[]{1, 2, 3};

        computeTime = -System.currentTimeMillis();
        byte[] tag = macHelper.computeMAC(hashData, key);
        computeTime += System.currentTimeMillis();

        verifyTime = -System.currentTimeMillis();
        macHelper.verifyMAC(hashData, tag, key);
        verifyTime += System.currentTimeMillis();
        System.out.printf("Mac algorithm %s (%d ms and %d ms passed): compute %.3fkb/sec verify %.3fkb/sec",
                macAlgorithmName,computeTime, verifyTime,
                (size / 1024.0) / (computeTime / 1000.0), (size / 1024.0) / (verifyTime / 1000.0));
    }
}
