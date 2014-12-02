package at.archistar.crypto.mac;

import at.archistar.crypto.informationchecking.CevallosUSRSS;
import at.archistar.crypto.random.FakeRandomSource;
import at.archistar.crypto.random.RandomSource;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(value = Parameterized.class)
public class VariableLengthMacPerformanceTest {

    private final byte[] key;
    
    private final byte[] data;
    
    private final int t;

    public VariableLengthMacPerformanceTest(byte[] key, byte[] data, int t) {
        this.key = key;
        this.data = data;
        this.t = t;
    }

    @Parameterized.Parameters
    public static Collection<Object[]> data() {
                
        RandomSource rng = new FakeRandomSource();

        byte[] key = new byte[32];
        byte[] data = new byte[1024*1024];
        
        rng.fillBytes(data);
        rng.fillBytes(key);
        
        /* prepare SIP key */
        byte[] sipKey = new byte[128/8];
        rng.fillBytes(sipKey);
        
        Object[][] params = new Object[][]{
            {key, data, 1},
            {key, data, 2}
        };

        return Arrays.asList(params);
    }

    @Test
    public void testPerformanceCreateVariableLength() throws NoSuchAlgorithmException, InvalidKeyException  {
        
        MacHelper mac = new BCShortenedMacHelper(new BCPoly1305MacHelper(), CevallosUSRSS.computeTagLength(data.length, t, CevallosUSRSS.E));
        
        long start = System.currentTimeMillis();
        for (int i = 0; i < 500; i++) {
            mac.computeMAC(data, key);
        }
        long end = System.currentTimeMillis();
        
        System.out.println(mac.toString() + " t: " + t + ": 500 * 1MB in " + (end - start) + "ms");
    }
}
