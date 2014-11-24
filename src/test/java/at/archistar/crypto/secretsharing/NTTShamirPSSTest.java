package at.archistar.crypto.secretsharing;

import at.archistar.crypto.data.Share;
import at.archistar.crypto.decode.BerlekampWelchDecoderFactory;
import at.archistar.crypto.decode.Decoder;
import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.decode.ErasureDecoderFactory;
import at.archistar.crypto.decode.UnsolvableException;
import at.archistar.crypto.exceptions.ReconstructionException;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.math.GF;
import at.archistar.crypto.math.gf257.GF257Factory;
import at.archistar.crypto.math.ntt.AbstractNTT;
import at.archistar.crypto.math.ntt.NTTSlow;
import at.archistar.crypto.random.FakeRandomSource;
import at.archistar.crypto.random.RandomSource;
import org.bouncycastle.util.Arrays;
import static org.fest.assertions.api.Assertions.assertThat;
import org.junit.Test;

/**
 *
 * @author andy
 */
public class NTTShamirPSSTest {
    
    private static final GF257Factory gffactory = new GF257Factory();
    
    private static final GF gf = gffactory.createHelper();

    private final int NTTBlockLength = 256;

    private final AbstractNTT ntt = new NTTSlow(gf);
    
    private final RandomSource rng = new FakeRandomSource();
    
    private static final int n = 7;
    
    private static final int k = 3;
    
    private final int blockCount = NTTBlockLength / n;
    
    private final static int generator = 3;
    
    private int[] createData(int size) {
        int[] tmp = new int[size];
        
        /* prepare test data */
        for (int i = 0; i < size; i++) {
            tmp[i] = i%256;
        }
        return tmp;
    }

    private byte[] createDataByte(int size) {
        byte[] tmp = new byte[size];
        
        /* prepare test data */
        for (int i = 0; i < size; i++) {
            tmp[i] = (byte)(i%256);
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
        int[] xValues = NTTShamirPSS.prepareXValuesFor(generator, gf);
        int minLength = (NTTBlockLength/n)*k;
        DecoderFactory decoderFactory = new ErasureDecoderFactory(gffactory);

        /* encode */
        NTTShamirPSS nttPSS = new NTTShamirPSS(n, k, generator, gffactory, rng, ntt, decoderFactory);
        int[] encodedData = new int[NTTBlockLength];
        nttPSS.encodeData(encodedData, data, 0, 1);        
        int[] encoded = ntt.ntt(encodedData, generator);
        
        /* decode */
        int[] yValues = new int[minLength];

        /* take minValue results and use them as input */
        System.arraycopy(encoded, 0, yValues, 0, minLength);
        int[] resultXValues = Arrays.copyOf(xValues, minLength);
        Decoder decoder = decoderFactory.createDecoder(resultXValues, minLength);
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
        
        int[] xValues = NTTShamirPSS.prepareXValuesFor(generator, gf);
        int minLength = (NTTBlockLength/n)*k;
        int[] resultXValues = Arrays.copyOf(xValues, minLength);
        DecoderFactory decoderFactory = new ErasureDecoderFactory(gffactory);

        /* encode */
        NTTShamirPSS nttPSS = new NTTShamirPSS(n, k, generator, gffactory, rng, ntt, decoderFactory);
        int[] encodedData = new int[NTTBlockLength];
        nttPSS.encodeData(encodedData, data, 0, blockCount);
        int[] encoded = ntt.ntt(encodedData, generator);
        
        /* decode */
        int[] yValues = new int[minLength];

        /* take minValue results and use them as input */
        System.arraycopy(encoded, 0, yValues, 0, minLength);
        Decoder decoder = decoderFactory.createDecoder(resultXValues, minLength);
        int[] result = decoder.decode(yValues, 0);

        for (int i = 0; i < blockCount; i++) {
            assertThat(result[i]).isEqualTo(data[i]);
        }
    }

    /**
     * test if an encryption round finishes
     */
    @Test
    public void encodeTest() throws WeakSecurityException {
        int[] data = createData(4096);
        DecoderFactory decoderFactory = new ErasureDecoderFactory(gffactory);
        NTTShamirPSS nttPSS = new NTTShamirPSS(n, k, generator, gffactory, rng, ntt, decoderFactory);
        
        nttPSS.encode(data);
    }

    /**
     * test with odd data count
     */
    @Test
    public void testUngeradeDatenMenge() throws UnsolvableException, WeakSecurityException {
        
        int[] data = createData(1023);
        int[] xValues = NTTShamirPSS.prepareXValuesFor(generator, gf);
        int minLength = (NTTBlockLength/n)*k;
        int[] resultXValues = Arrays.copyOf(xValues, minLength);
        DecoderFactory decoderFactory = new ErasureDecoderFactory(gffactory);

        NTTShamirPSS nttPSS = new NTTShamirPSS(n, k, generator, gffactory, rng, ntt, decoderFactory);
        int[][] output = nttPSS.encode(data);
        
        /* copy k Elements */
        int[][] resultOutput = new int[k][];
        System.arraycopy(output, 0, resultOutput, 0, k);
        
        int[] result = nttPSS.reconstruct(resultOutput, resultXValues, data.length);
        assertThat(result).isEqualTo(data);
    }
    
    @Test
    public void reconstructTest() throws UnsolvableException, WeakSecurityException {
        int[] data = createData(4096);
        int[] xValues = NTTShamirPSS.prepareXValuesFor(generator, gf);
        int minLength = (NTTBlockLength/n)*k;
        int[] resultXValues = Arrays.copyOf(xValues, minLength);
        DecoderFactory decoderFactory = new ErasureDecoderFactory(gffactory);
        
        NTTShamirPSS nttPSS = new NTTShamirPSS(n, k, generator, gffactory, rng, ntt, decoderFactory);
        int[][] output = nttPSS.encode(data);
        
        /* copy k Elements */
        int[][] resultOutput = new int[k][];
        System.arraycopy(output, 0, resultOutput, 0, k);
        
        int[] result = nttPSS.reconstruct(resultOutput, resultXValues, data.length);
        assertThat(result).isEqualTo(data);
    }
    
    @Test
    public void reconstructBWTest() throws UnsolvableException, WeakSecurityException {
        
        int[] data = createData(4096);
        int[] xValues = NTTShamirPSS.prepareXValuesFor(generator, gf);
        int minLength = (NTTBlockLength/n)*k;
        int[] resultXValues = Arrays.copyOf(xValues, minLength);
        DecoderFactory decoderFactory = new BerlekampWelchDecoderFactory(gffactory);
        
        NTTShamirPSS nttPSS = new NTTShamirPSS(n, k, generator, gffactory, rng, ntt, decoderFactory);
        
        int[][] output = nttPSS.encode(data);
        
        /* copy k Elements */
        int[][] resultOutput = new int[k][];
        System.arraycopy(output, 0, resultOutput, 0, k);
        
        int[] result = nttPSS.reconstruct(resultOutput, resultXValues, data.length);
        assertThat(result).isEqualTo(data);
    }
    
    @Test
    public void shareReconstructCycle() throws WeakSecurityException, ReconstructionException {
        byte[] data = createDataByte(4096);
        DecoderFactory decoderFactory = new ErasureDecoderFactory(gffactory);
        
        NTTShamirPSS nttPSS = new NTTShamirPSS(n, k, generator, gffactory, rng, ntt, decoderFactory);
        
        Share[] shares = nttPSS.share(data);
        
        /* take k shares */
        Share[] kShares = new Share[k];
        System.arraycopy(shares, 0, kShares, 0, k);
        
        byte[] result = nttPSS.reconstruct(kShares);
        
        assertThat(result).isEqualTo(data);
    }
}
