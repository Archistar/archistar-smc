package at.archistar.crypto.secretsharing;

import at.archistar.crypto.decode.BerlekampWelchDecoder;
import at.archistar.crypto.decode.Decoder;
import at.archistar.crypto.decode.ErasureDecoder;
import at.archistar.crypto.decode.UnsolvableException;
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
public class NTTEncode {
    
    private static final GF257Factory gffactory = new GF257Factory();
    
    private static final GF gf = gffactory.createHelper();

    private final int NTTBlockLength = 256;

    private final AbstractNTT ntt = new NTTSlow(gf);
    
    private final RandomSource rng = new FakeRandomSource();
    
    private static final int n = 7;
    
    private static final int k = 3;
    
    private final int blockCount = NTTBlockLength / n;
    
    private static final int dataLength = 4096;
    
    private static final int data[];
    
    private final static int generator = 3;
    
    private static final int xValues[];
    
    static {
        data = new int[dataLength];
        
        /* prepare test data */
        for (int i = 0; i < dataLength; i++) {
            data[i] = i%256;
        }
        
        /* prepare all possible xValues */
        xValues= new int[256];
        
        xValues[0] = 1;
        for (int i = 1; i < 256; i++) {
            xValues[i] = gf.mult(xValues[i-1], generator);
        }
    }
    
    @Test
    public void testGenerator() {
        for (int i = 0; i < 255; i++) {
            for (int j = i+1; j < 256; j++) {
                assertThat(xValues[i]).isNotEqualTo(xValues[j]);
            }
        }
    }
    
    @Test
    public void testUngeradeDatenMenge() throws UnsolvableException {
        
        int data2[] = new int[1023];
        for (int i = 0; i < data2.length; i++) {
            data2[i] = i%256;
        }
        
        int[][] output = encode(data2);
        
        int minLength = (NTTBlockLength/n)*k;
        int[] resultXValues = Arrays.copyOf(xValues, minLength);
        int[][] resultOutput = new int[k][];
        
        System.arraycopy(output, 0, resultOutput, 0, k);
        
        Decoder decoder = new BerlekampWelchDecoder(resultXValues, minLength, gffactory);
        int[] result = reconstruct(resultOutput, resultXValues, data2.length, decoder);
        assertThat(result).isEqualTo(data2);
    }

    @Test
    public void testBuildDecoder() {
        int minLength = (NTTBlockLength/n)*k;
        
        /* limit to k results */
        int[] resultXValues = Arrays.copyOf(xValues, minLength);
        
        /* create decoder */
        Decoder decoder = new ErasureDecoder(resultXValues, minLength, gffactory);
        assertThat(decoder).isNotNull();
    }

    @Test
    public void testBuildBWDecoder() {
        int minLength = (NTTBlockLength/n)*k;
        
        /* limit to k results */
        int[] resultXValues = Arrays.copyOf(xValues, minLength);
        
        /* create decoder */
        Decoder decoder = new BerlekampWelchDecoder(resultXValues, minLength, gffactory);
        assertThat(decoder).isNotNull();
    }
    
     @Test
    public void encodeDecodeCycle1Byte() throws UnsolvableException {
        
        int[] wip = new int[256];

        /* add data */
        wip[0] = 42;

        /* add random */
        wip[1] = 4;
        wip[2] = 4;
        
        int[] conv = ntt.ntt(wip, generator);
        
        /* decode */
        int minLength = (NTTBlockLength/n)*k;
        int[] resultXValues = Arrays.copyOf(xValues, minLength);
        int[] yValues = new int[minLength];

        /* take minValue results and use them as input */
        System.arraycopy(conv, 0, yValues, 0, minLength);
        
        Decoder decoder = new ErasureDecoder(resultXValues, minLength, gffactory);
        int[] result = decoder.decode(yValues, 0);

        assertThat(result[0]).isEqualTo(42);
    }

    /*
     * test a single encrypt/decrypt round without any packing
     */
    @Test
    public void encodeDecodeCycle() throws UnsolvableException {
        
        int[] wip = new int[256];

        /* add Data */
        System.arraycopy(data, 0, wip, 0, blockCount);
        
        /* add random */
        int[] random = new int[blockCount * (k - 1)];
        rng.fillBytesAsInts(random);
        System.arraycopy(random, 0, wip, blockCount, random.length);

        int[] conv = ntt.ntt(wip, generator);
        
        /* decode */
        int minLength = (NTTBlockLength/n)*k;
        int[] resultXValues = Arrays.copyOf(xValues, minLength);
        int[] yValues = new int[minLength];

        /* take minValue results and use them as input */
        System.arraycopy(conv, 0, yValues, 0, minLength);
        
        Decoder decoder = new ErasureDecoder(resultXValues, minLength, gffactory);
        int[] result = decoder.decode(yValues, 0);

        for (int i = 0; i < blockCount; i++) {
            assertThat(result[i]).isEqualTo(data[i]);
        }
    }
    
    private int[][] encode(int[] data) {
        
        int resultSize = ((data.length / blockCount)+1)*blockCount;
        
        int[][] output = new int[n][resultSize];

        for (int i = 0; i < (data.length / blockCount)+1; i++) {
            int[] tmp = new int[NTTBlockLength]; // initialized with 0

            int copyLength = (blockCount * (i+1) < data.length) ? blockCount : (data.length % blockCount);
            System.arraycopy(data, blockCount * i, tmp, 0, copyLength);

            /* (k-1) -- shamir uses 1 byte secret and (k-1) byte randomness */
            int[] random = new int[copyLength * (k - 1)];
            rng.fillBytesAsInts(random);

            System.arraycopy(random, 0, tmp, blockCount, random.length);

            int[] conv = ntt.ntt(tmp, generator);
            for (int j = 0; j < n; j++) {
                System.arraycopy(conv, j*blockCount, output[j], i*blockCount, blockCount);
            }
        }
        return output;        
    }
    
    @Test
    public void encodeTest() {
        encode(data);
    }
    
    private int[] reconstruct(int[][] encoded, int[] xValues, int origLength, Decoder decoder) throws UnsolvableException {

        int minLength = (NTTBlockLength/n)*k;
        
        /* expect a minimum of k parts */
        assert(encoded.length >= k);
        
        /* check that all parts are of the same length */
        int length = encoded[0].length;
        for (int i = 1; i < encoded.length; i++) {
            assertThat(length).isEqualTo(encoded[i].length);
        }
        
        int result[] = new int[origLength];
        int resultPos = 0;

        for (int i = 0; i < length/blockCount; i++) {
            
            int yValues[] = new int[minLength];
            
            /* assume everything to be in the same order and xValues start with 1 */
            for (int j = 0; j < encoded.length; j++) {
              System.arraycopy(encoded[j], i*blockCount, yValues, j*blockCount, blockCount);
            }
            
            int[] tmp = decoder.decode(yValues, 0);
            
            int copyLength = blockCount;
            if (blockCount > (origLength - resultPos)) {
                copyLength = origLength - resultPos;
            }
            
            /* for (int x = 0; x < copyLength; x++) {
                result[resultPos++] = (tmp[x] < 0) ? (tmp[x] + 256) : tmp[x];
            }*/
            
            System.arraycopy(tmp, 0, result, resultPos, copyLength);
            resultPos += copyLength;
        }
        
        if (origLength != result.length) {
            result = Arrays.copyOf(result, origLength);
        }
        return result;
    }
    
    @Test
    public void reconstructTest() throws UnsolvableException {
        int[][] output = encode(data);
        
        int minLength = (NTTBlockLength/n)*k;
        int[] resultXValues = Arrays.copyOf(xValues, minLength);
        int[][] resultOutput = new int[k][];
        
        System.arraycopy(output, 0, resultOutput, 0, k);
        
        Decoder decoder = new ErasureDecoder(resultXValues, minLength, gffactory);
        int[] result = reconstruct(resultOutput, resultXValues, 4096, decoder);
        assertThat(result).isEqualTo(data);
    }
    
    @Test
    public void reconstructBWTest() throws UnsolvableException {
        int[][] output = encode(data);
        
        int minLength = (NTTBlockLength/n)*k;
        int[] resultXValues = Arrays.copyOf(xValues, minLength);
        int[][] resultOutput = new int[k][];
        
        System.arraycopy(output, 0, resultOutput, 0, k);
        
        Decoder decoder = new BerlekampWelchDecoder(resultXValues, minLength, gffactory);
        int[] result = reconstruct(resultOutput, resultXValues, 4096, decoder);
        assertThat(result).isEqualTo(data);
    }
}
