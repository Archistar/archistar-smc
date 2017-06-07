package at.archistar.crypto.informationchecking;

import at.archistar.TestHelper;
import at.archistar.crypto.CryptoEngineFactory;
import at.archistar.crypto.PSSEngine;
import at.archistar.crypto.data.InformationCheckingShare;
import at.archistar.crypto.mac.BCPoly1305MacHelper;
import at.archistar.crypto.mac.JavaMacHelper;
import at.archistar.crypto.mac.MacHelper;
import at.archistar.crypto.random.FakeRandomSource;
import at.archistar.crypto.random.RandomSource;
import at.archistar.crypto.secretsharing.WeakSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;

/**
 * Test information checking performance by calling create/check-tags upon a
 * Share. Repeat this a couple of times (until TEST_SIZE incoming Data was
 * processed to create more repeatable results.
 */
@RunWith(value = Parameterized.class)
public class PerformanceTest {

    private final InformationCheckingShare[][] input;
    private final InformationChecking ic;

    public PerformanceTest(InformationCheckingShare[][] input, InformationChecking ic) {
        this.input = input;
        this.ic = ic;
    }

    private static byte[] createData(int size) {
        byte[] tmp = new byte[size];

        /* prepare test data */
        for (int i = 0; i < size; i++) {
            tmp[i] = (byte) (i % 256);
        }
        return tmp;
    }

    @Parameterized.Parameters
    public static Collection<Object[]> data() throws WeakSecurityException, NoSuchAlgorithmException {

        System.err.println("Data-Size per Test: " + TestHelper.TEST_SIZE / 1024 / 1024 + "MByte");

        final int n = 5;
        final int k = 3;

        RandomSource rng = new FakeRandomSource();
        MacHelper mac = new JavaMacHelper("HMacSHA256");
        MacHelper macPoly1305 = new BCPoly1305MacHelper();
        PSSEngine secretSharing = CryptoEngineFactory.getPSSEngine(n, k, rng);

        InformationCheckingShare[][] shares = new InformationCheckingShare[][]{
                secretSharing.share(createData(4 * 1024)),
                secretSharing.share(createData(128 * 1024)),
                secretSharing.share(createData(512 * 1024)),
                secretSharing.share(createData(4096 * 1024)),
        };

        Object[][] data = new Object[][]{
                {shares, new CevallosUSRSS(n, k, mac, rng)},
                {shares, new CevallosUSRSS(n, k, macPoly1305, rng)},
                {shares, new RabinBenOrRSS(k, mac, rng)},
                {shares, new RabinBenOrRSS(k, macPoly1305, rng)}
        };

        return Arrays.asList(data);
    }

    @Test
    public void testPerformance() throws Exception {
        for (InformationCheckingShare[] shares : input) {
            double sumCreate = 0;
            double sumCheck = 0;

            int done = 0;
            for (int j = 0; j < TestHelper.TEST_SIZE / shares[0].getYValues().length; j++) {
                for (InformationCheckingShare s : shares) {
                    s.getMacs().clear();
                    s.getMacKeys().clear();
                }
                long beforeCreate = System.currentTimeMillis();
                ic.createTags(shares);
                long betweenOperations = System.currentTimeMillis();
                ic.checkShares(shares);
                long afterAll = System.currentTimeMillis();

                sumCreate += (betweenOperations - beforeCreate);
                sumCheck += (afterAll - betweenOperations);
                done++;
            }
            double createPerSec = done / (sumCreate / 1000.0);
            double checkPerSec = done / (sumCheck / 1000.0);
            double shareSize = shares[0].getYValues().length / 1024;

            System.err.format("%41s %4.0fkB %5.1f/sec %4.0fkB/sec %5.1f/sec %4.0fkB/sec\n", ic, shareSize, createPerSec, createPerSec * shareSize, checkPerSec, checkPerSec * shareSize);
        }
    }
}
