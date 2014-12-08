package at.archistar.crypto.mac;

import at.archistar.crypto.random.FakeRandomSource;
import at.archistar.crypto.random.RandomSource;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 * benchmark our fixed-length macs
 */
@RunWith(value = Parameterized.class)
public class FixedLengthMacPerformanceTest {

    private final MacHelper mac;
    
    private final byte[] key;
    
    private final byte[] data;

    public FixedLengthMacPerformanceTest(byte[] key, byte[] data, MacHelper mac) {
        this.mac = mac;
        this.key = key;
        this.data = data;
    }

    @Parameterized.Parameters
    public static Collection<Object[]> data() throws NoSuchAlgorithmException {
        
        System.err.println("All tests on 500MB data a 1MB chunks");

        RandomSource rng = new FakeRandomSource();

        byte[] key = new byte[32];
        byte[] data = new byte[1024*1024];
        
        rng.fillBytes(data);
        rng.fillBytes(key);
        
        /* prepare SIP key */
        byte[] sipKey = new byte[128/8];
        rng.fillBytes(sipKey);
        
        Object[][] params = new Object[][]{
            {key, data, new ShareMacHelper("HMacSHA256")},
            {key, data, new BCMacHelper(new HMac(new SHA256Digest()), key.length) },
            {key, data, new BCPoly1305MacHelper() },
        };

        return Arrays.asList(params);
    }

    @Test
    public void testPerformanceCreateFixedLength() throws InvalidKeyException {
        
        long start = System.currentTimeMillis();
        for (int i = 0; i < 500; i++) {
            this.mac.computeMAC(data, key);
        }
        long end = System.currentTimeMillis();

        System.err.format("%50s %6dms\n", mac, end - start);
    }
}
