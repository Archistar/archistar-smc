package at.archistar.crypto.secretsharing;

import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.decode.ErasureDecoderFactory;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.math.GF;
import at.archistar.crypto.math.gf257.GF257Factory;
import at.archistar.crypto.math.ntt.AbstractNTT;
import at.archistar.crypto.math.ntt.NTTSlow;
import org.junit.Before;

/**
 *
 * @author andy
 */
public class NTTRabinIDSTest extends BasicSecretSharingTest {
    
    private static final int generator = 3;
    
    public NTTRabinIDSTest() {
        super(4, 3);
    }
    
    @Before
    public void setup() throws WeakSecurityException {
        GF257Factory gffactory = new GF257Factory();
        DecoderFactory df = new ErasureDecoderFactory(gffactory);
        GF gf = gffactory.createHelper();
        AbstractNTT ntt = new NTTSlow(gf);
        algorithm = new NTTRabinIDS(n, k, generator, gffactory, ntt, df);
    }
}
