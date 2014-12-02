package at.archistar.crypto.secretsharing;

import at.archistar.crypto.data.Share;
import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.decode.ErasureDecoderFactory;
import at.archistar.crypto.exceptions.ReconstructionException;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.math.GF;
import at.archistar.crypto.math.gf257.GF257Factory;
import at.archistar.crypto.math.ntt.AbstractNTT;
import at.archistar.crypto.math.ntt.NTTSlow;
import static org.fest.assertions.api.Assertions.assertThat;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author andy
 */
public class NTTRabinIDSTest {
    
    private static final int generator = 3;
    
    private SecretSharing algorithm;
    
    private final int n;
    
    private final int k;
    
    public NTTRabinIDSTest() {
        //super(4, 3);
        n = 4;
        k = 3;
    }
    
    @Before
    public void setup() throws WeakSecurityException {
        GF257Factory gffactory = new GF257Factory();
        DecoderFactory df = new ErasureDecoderFactory(gffactory);
        GF gf = gffactory.createHelper();
        AbstractNTT ntt = new NTTSlow(gf);
        algorithm = new NTTRabinIDS(n, k, generator, gffactory, ntt, df);
    }

    private byte[] createDataByte(int size) {
                
        byte[] tmp = new byte[size];
        
        /* prepare test data */
        for (int i = 0; i < size; i++) {
            tmp[i] = (byte)(i%256);
        }
        return tmp;
    }
    
    @Test
    public void shareReconstructCycle() throws WeakSecurityException, ReconstructionException {
        byte[] data2 = createDataByte(4096);
        
        Share[] shares = algorithm.share(data2);
        
        /* take k shares */
        Share[] kShares = new Share[k];
        System.arraycopy(shares, 0, kShares, 0, k);
        
        byte[] result = algorithm.reconstruct(kShares);
        
        assertThat(result).isEqualTo(data2);
    }
}
