package at.archistar.crypto.mac;

import at.archistar.crypto.CevallosUSRSS;
import at.archistar.crypto.exceptions.CryptoException;
import at.archistar.crypto.random.FakeRandomSource;
import at.archistar.crypto.random.RandomSource;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.macs.SipHash;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(value = Parameterized.class)
public class MacPerformanceTest {

    private final MacHelper mac;
    
    private final byte[] key;
    
    private final byte[] data;

    public MacPerformanceTest(byte[] key, byte[] data, MacHelper mac) throws CryptoException {
        this.mac = mac;
        this.key = key;
        this.data = data;
    }

    @Parameterized.Parameters
    public static Collection<Object[]> data() throws CryptoException, NoSuchAlgorithmException {
                
        RandomSource rng = new FakeRandomSource();

        byte[] key = new byte[32];
        byte[] data = new byte[1024*1024];
        
        rng.fillBytes(data);
        rng.fillBytes(key);
        
        byte[] theKey = new byte[CevallosUSRSS.computeTagLength(data.length, 3, CevallosUSRSS.E)];
        byte[] sipKey = new byte[128/8];
        
        rng.fillBytes(theKey);
        rng.fillBytes(sipKey);
        
        System.out.println("keylength shortened: " + theKey.length);
        
        Object[][] params = new Object[][]{
            {key, data, new ShareMacHelper("HMacSHA256")},
            {key, data, new BCMacHelper(new HMac(new SHA256Digest()), key.length) },
            {sipKey, data, new BCMacHelper(new SipHash(), sipKey.length) },
            {key, data, new BCPoly1305MacHelper() },
            {theKey, data, new ShortenedMacHelper("HMacSHA256", 3, CevallosUSRSS.E) }
        };

        return Arrays.asList(params);
    }

    @Test
    public void testPerformanceCreate() throws InvalidKeyException {
        
        long start = System.currentTimeMillis();
        for (int i = 0; i < 500; i++) {
            this.mac.computeMAC(data, key);
        }
        long end = System.currentTimeMillis();

        System.out.println(this.mac.toString() + ": 500 * 1MB in " + (end - start) + "ms");
    }
}
