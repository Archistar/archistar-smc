package at.archistar.crypto.informationchecking;

import at.archistar.TestHelper;
import at.archistar.crypto.data.SerializableShare;
import at.archistar.crypto.data.VSSShare;
import at.archistar.crypto.decode.ErasureDecoderFactory;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.mac.BCPoly1305MacHelper;
import at.archistar.crypto.mac.MacHelper;
import at.archistar.crypto.mac.ShareMacHelper;
import at.archistar.crypto.math.GFFactory;
import at.archistar.crypto.math.gf256.GF256Factory;
import at.archistar.crypto.random.FakeRandomSource;
import at.archistar.crypto.random.RandomSource;
import at.archistar.crypto.secretsharing.KrawczykCSS;
import at.archistar.crypto.secretsharing.BaseSecretSharing;
import at.archistar.crypto.symmetric.ChaCha20Encryptor;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author andy
 */
@RunWith(value = Parameterized.class)
public class Benchmark {
    
    private final byte[][][] input;
    private final BaseSecretSharing algorithm;
    private final InformationChecking ic;
    
    @Parameterized.Parameters
    public static Collection<Object[]> data() throws WeakSecurityException, NoSuchAlgorithmException {
        
        System.err.println("Data-Size per Test: " + TestHelper.TEST_SIZE/1024/1024 + "MByte");

        byte[][][] secrets = new byte[4][][];
        secrets[0] = TestHelper.createArray(4 * 1024);       // typical file system block size
        secrets[1] = TestHelper.createArray(128 * 1024);     // documents
        secrets[2] = TestHelper.createArray(512 * 1024);     // documents, pictures (jpegs)
        secrets[3] = TestHelper.createArray(4096 * 1024);    // audio, high-quality pictures

        final int n = 4;
        final int k = 3;

        RandomSource rng = new FakeRandomSource();
        MacHelper mac = new ShareMacHelper("HMacSHA256");
        MacHelper macPoly1305 = new BCPoly1305MacHelper();
        
        GFFactory gffactory = new GF256Factory();
        BaseSecretSharing secretSharing = new KrawczykCSS(5, 3, rng, new ChaCha20Encryptor(), new ErasureDecoderFactory(gffactory), gffactory.createHelper());
        
        Object[][] data = new Object[][]{
           {secrets, secretSharing, new CevallosUSRSS(secretSharing, mac, rng)},
           {secrets, secretSharing, new CevallosUSRSS(secretSharing, macPoly1305, rng)},
           {secrets, secretSharing, new RabinBenOrRSS(secretSharing, mac, rng)},
           {secrets, secretSharing, new RabinBenOrRSS(secretSharing, macPoly1305, rng)}
        };

        return Arrays.asList(data);
    }
    
    public Benchmark(byte[][][] input, BaseSecretSharing algorithm, InformationChecking ic) {
        this.input = input;
        this.algorithm = algorithm;
        this.ic = ic;
    }

    @Test
    public void testPerformance() throws Exception {
        for (int i = 0; i < input.length; i++) {
            double sumCreate = 0;
            double sumCheck = 0;

            for (byte[] data : this.input[i]) {
                
                SerializableShare[] shares = (SerializableShare[])algorithm.share(data);
                VSSShare[] vssshares = new VSSShare[shares.length];

                for (int j = 0; j < shares.length; j++) {
                    vssshares[j] = new VSSShare(shares[j]);
                }

                long beforeCreate = System.currentTimeMillis();
                ic.createTags(vssshares);
                long betweenOperations = System.currentTimeMillis();
                ic.checkShares(vssshares);
                long afterAll = System.currentTimeMillis();

                sumCreate += (betweenOperations - beforeCreate);
                sumCheck += (afterAll - betweenOperations);
            }
            System.err.format("Performance(%dkB file size) of %s: create: %.3fkByte/sec, check: %.2fkByte/sec\n", this.input[i][0].length/1024, this.algorithm, (TestHelper.TEST_SIZE / 1024) / (sumCreate / 1000.0), (TestHelper.TEST_SIZE / 1024) / (sumCheck / 1000.0));
        }
    }
}