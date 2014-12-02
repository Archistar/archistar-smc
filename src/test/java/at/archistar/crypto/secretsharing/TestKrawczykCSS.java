package at.archistar.crypto.secretsharing;

import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.decode.ErasureDecoderFactory;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.math.GF;
import at.archistar.crypto.math.GFFactory;
import at.archistar.crypto.math.gf256.GF256Factory;
import at.archistar.crypto.random.FakeRandomSource;
import at.archistar.crypto.symmetric.AESEncryptor;
import org.junit.Before;

/**
 * Test for {@link KrawczykCSS}
 */
public class TestKrawczykCSS extends BasicSecretSharingTest {

    public TestKrawczykCSS() {
        super(8, 5);
    }

    /* setup and tear-down */
    @Before
    public void setup() throws WeakSecurityException {
        
        GFFactory gffactory = new GF256Factory();
        DecoderFactory df = new ErasureDecoderFactory(gffactory);
        GF gf = gffactory.createHelper();
        
        algorithm = new KrawczykCSS(n, k, new FakeRandomSource(), new AESEncryptor(), df, gf);
    }
}
