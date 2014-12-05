package at.archistar.crypto.secretsharing;

import at.archistar.crypto.decode.Decoder;
import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.decode.ErasureDecoderFactory;
import at.archistar.crypto.decode.UnsolvableException;
import at.archistar.crypto.math.EncodingConverter;
import at.archistar.crypto.math.GF;
import at.archistar.crypto.math.OutputEncoderConverter;
import at.archistar.crypto.math.gf257.GF257Factory;
import at.archistar.crypto.math.ntt.AbstractNTT;
import at.archistar.crypto.math.ntt.NTTSlow;
import at.archistar.crypto.random.FakeRandomSource;
import at.archistar.crypto.random.RandomSource;
import org.bouncycastle.util.Arrays;
import static org.fest.assertions.api.Assertions.assertThat;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author andy
 */
public class NTTShamirPSSTest extends BasicSecretSharingTest {
    
    private final int NTTBlockLength = 256;
   
    private final int blockCount = NTTBlockLength / n;
    
    private final static int generator = 3;
    
    private final GF gf;
    
    private final GF257Factory gffactory;
    
    private final DecoderFactory df;
    
    private final AbstractNTT ntt;
    
    private final RandomSource random;
    
    private final int minLength = (NTTBlockLength/n)*k;
    
    private final int[] xValues;
    
    private final int[] resultXValues;
    
    public NTTShamirPSSTest() {
        super(7, 3);

        gffactory = new GF257Factory();
        df = new ErasureDecoderFactory(gffactory);
        gf = gffactory.createHelper();
        ntt = new NTTSlow(gf);
        random = new FakeRandomSource();
        xValues = NTTShamirPSS.prepareXValuesFor(generator, gf);
        resultXValues = Arrays.copyOf(xValues, minLength);
    }
    
    @Before
    public void setup() throws WeakSecurityException {
        algorithm = new NTTShamirPSS(n, k, generator, gffactory, random, ntt, df);
    }
    
    private int[] createData(int size) {
        int[] tmp = new int[size];
        
        /* prepare test data */
        for (int i = 0; i < size; i++) {
            tmp[i] = i%256;
        }
        return tmp;
    }

    /**
     * test if generated values are really unique (otherwise we wouldn't have
     * a generator, wouldn't we?
     */
    @Test
    public void testGenerator() {
        
        int tmp[] = NTTShamirPSS.prepareXValuesFor(generator, gf);

        for (int i = 0; i < 255; i++) {
            for (int j = i+1; j < 256; j++) {
                assertThat(tmp[i]).isNotEqualTo(tmp[j]);
            }
        }
    }

    /**
     * Test if a single byte can be encoded
     * @throws UnsolvableException 
     */
    @Test
    public void encodeDecodeCycle1Byte() throws UnsolvableException, WeakSecurityException {
        
        final int dataElement = 42;
        int[] data = { dataElement };

        /* encode */
        int[] encodedData = new int[NTTBlockLength];
        NTTShamirPSS nttPSS = new NTTShamirPSS(n, k, generator, gffactory, random, ntt, df);

        nttPSS.encodeData(encodedData, data, 0, 1);        
        int[] encoded = ntt.ntt(encodedData, generator);
        
        /* decode */
        int[] yValues = new int[minLength];

        /* take minValue results and use them as input */
        System.arraycopy(encoded, 0, yValues, 0, minLength);
        Decoder decoder = df.createDecoder(resultXValues, minLength);
        int[] result = decoder.decode(yValues, 0);

        assertThat(result[0]).isEqualTo(dataElement);
    }
    
        /*
     * test a single encrypt/decrypt round without any packing
     */
    @Test
    public void encodeDecodeCycle() throws UnsolvableException, WeakSecurityException {
        
        int[] wip = new int[256];
        int[] data = createData(blockCount);

        /* encode */
        NTTShamirPSS nttPSS = new NTTShamirPSS(n, k, generator, gffactory, random, ntt, df);
        int[] encodedData = new int[NTTBlockLength];
        nttPSS.encodeData(encodedData, data, 0, blockCount);
        int[] encoded = ntt.ntt(encodedData, generator);
        
        /* decode */
        int[] yValues = new int[minLength];

        /* take minValue results and use them as input */
        System.arraycopy(encoded, 0, yValues, 0, minLength);
        Decoder decoder = df.createDecoder(resultXValues, minLength);
        int[] result = decoder.decode(yValues, 0);

        for (int i = 0; i < blockCount; i++) {
            assertThat(result[i]).isEqualTo(data[i]);
        }
    }

    /**
     * test with odd data count
     */
    @Test
    public void testOddDatenMenge() throws WeakSecurityException, UnsolvableException {
        
        int[] data = createData(1023);

        NTTShamirPSS nttPSS = new NTTShamirPSS(n, k, generator, gffactory, random, ntt, df);
        OutputEncoderConverter[] output = nttPSS.encode(data);
        
        /* copy k Elements */
        int[][] tmp = new int[k][];
        for(int i = 0; i < k; i++) {
            tmp[i] = new EncodingConverter(output[i].getEncodedData(), gf).getDecodedData();
        }
        
        int[] result = nttPSS.reconstruct(tmp, resultXValues, data.length);
        
        //int[] result = nttPSS.reconstruct(resultOutput, resultXValues, data.length);
        assertThat(result).isEqualTo(data);
    }
    
    @Test
    public void reconstructTest() throws UnsolvableException, WeakSecurityException {
        int[] data = createData(4096);
        
        NTTShamirPSS nttPSS = new NTTShamirPSS(n, k, generator, gffactory, random, ntt, df);
        
        OutputEncoderConverter[] output = nttPSS.encode(data);
        
        /* copy k Elements */
        int[][] tmp = new int[k][];
        for(int i = 0; i < k; i++) {
            tmp[i] = new EncodingConverter(output[i].getEncodedData(), gf).getDecodedData();
        }
        
        /* copy k Elements */
        int[][] resultOutput = new int[k][];
        System.arraycopy(tmp, 0, resultOutput, 0, k);
        
        int[] result = nttPSS.reconstruct(resultOutput, resultXValues, data.length);
        assertThat(result).isEqualTo(data);
    }
    
    @Test
    public void reconstructBWTest() throws UnsolvableException, WeakSecurityException {
        
        int[] data = createData(4096);
        NTTShamirPSS nttPSS = new NTTShamirPSS(n, k, generator, gffactory, random, ntt, df);

        OutputEncoderConverter[] output = nttPSS.encode(data);
        
        /* copy k Elements */
        int[][] tmp = new int[k][];
        for(int i = 0; i < k; i++) {
            tmp[i] = new EncodingConverter(output[i].getEncodedData(), gf).getDecodedData();
        }
        
        /* copy k Elements */
        int[][] resultOutput = new int[k][];
        System.arraycopy(tmp, 0, resultOutput, 0, k);
        
        int[] result = nttPSS.reconstruct(resultOutput, resultXValues, data.length);
        assertThat(result).isEqualTo(data);
    }
}
