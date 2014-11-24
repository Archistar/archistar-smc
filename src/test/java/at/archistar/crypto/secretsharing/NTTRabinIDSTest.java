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
import org.junit.Test;

/**
 *
 * @author andy
 */
public class NTTRabinIDSTest {
    
    private static final GF257Factory gffactory = new GF257Factory();
    
    private static final GF gf = gffactory.createHelper();
    
    private static final int n = 4;
    
    private static final int k = 3;
    
    private static final int generator = 3;
    
    private static final AbstractNTT ntt = new NTTSlow(gf);
    
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
        byte[] data = createDataByte(4096);
        DecoderFactory decoderFactory = new ErasureDecoderFactory(gffactory);
        
        SecretSharing nttPSS = new NTTRabinIDS(n, k, generator, gffactory, ntt, decoderFactory);
        
        Share[] shares = nttPSS.share(data);
        
        /* take k shares */
        Share[] kShares = new Share[k];
        System.arraycopy(shares, 0, kShares, 0, k);
        
        byte[] result = nttPSS.reconstruct(kShares);
        
        assertThat(result).isEqualTo(data);
    }
}
