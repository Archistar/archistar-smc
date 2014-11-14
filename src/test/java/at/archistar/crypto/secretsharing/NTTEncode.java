package at.archistar.crypto.secretsharing;

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
    
    private final GF257Factory gffactory = new GF257Factory();
    
    private final GF gf = gffactory.createHelper();

    private final int NTTBlockLength = 256;

    private final AbstractNTT ntt = new NTTSlow(this.gf);
    
    private final RandomSource rng = new FakeRandomSource();
    
    private final int n = 7;
    
    private final int k = 3;
    
    private final int blockCount = NTTBlockLength / n;
    
    @Test
    public void testGenerator() {
        
        int xValues[] = computeXValues(256, 3);
        for (int i = 0; i < 255; i++) {
            for (int j = i+1; j < 256; j++) {
                assertThat(xValues[i]).isNotEqualTo(xValues[j]);
            }
        }
    }

    private int[] computeXValues(int n, int generator) {
        int xValues[] = new int[256];
        
        xValues[0] = 1;
        for (int i = 1; i < n; i++) {
            xValues[i] = gf.mult(xValues[i-1], generator);
        }
        return xValues;
    }
    
    @Test
    public void testBuildDecoder() {
        int minLength = (NTTBlockLength/n)*k;
        
        /* create 256 results */
        int[] results = computeXValues(256, 3);
        
        /* limit to k results */
        int[] resultXValues = Arrays.copyOf(results, minLength);
        
        /* create decoder */
        Decoder decoder = new ErasureDecoder(resultXValues, minLength, gffactory);
        assertThat(decoder).isNotNull();
    }
    
    private int[][] encode(int[] data) {
        int[][] output = new int[n][data.length];

        for (int i = 0; i < (data.length / blockCount)+1; i++) {
            int[] tmp = new int[NTTBlockLength]; // initialized with 0

            int copyLength = (blockCount * (i+1) < data.length) ? blockCount : (data.length % blockCount);
            System.arraycopy(data, blockCount * i, tmp, 0, copyLength);

            /* (k-1) -- shamir uses 1 byte secret and (k-1) byte randomness */
            int[] random = new int[blockCount * (k - 1)];
            rng.fillBytesAsInts(random);

            System.arraycopy(random, 0, tmp, blockCount, random.length);

            int[] conv = ntt.ntt(tmp, 256);
            
            int pos = 0;
            for (int j = 0; j < n; j++) {
                for (int x = 0; x < blockCount; x++) {
                    // x-Value === j * dataLength + x
                    output[j][x] = conv[j * blockCount + x];
                }
            }
        }
        return output;        
    }
    
    @Test
    public void encodeTest() {
        
        /* encoding */
        int[] data = new int[4096];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte)i;
        }

        encode(data);
    }
    
    @Test
    public void reconstructTest() throws UnsolvableException {

        int[] xValues = computeXValues(256, 3);
        
        /* encoding */
        int[] data = new int[4096];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte)i;
        }
        
        int[][] output = encode(data);
        
        /* decoding, just one round -- assume everything is in the same order x/y Value wise */
        int[] yValues = new int[256];
        for (int j = 0; j < n; j++) {
            for (int h = 0; h < blockCount; h++) {
                yValues[j * blockCount + h] = output[j][h];
            }
        }
        
        /* this is k blown up to fill (block-length/n)
         * we asume a full block for now
        */
        int minLength = (NTTBlockLength/n)*k;
        int[] resultXValues = Arrays.copyOf(xValues, minLength);
        
        
        Decoder erasure = new ErasureDecoder(resultXValues, minLength, new GF257Factory());
        int[] result = erasure.decode(Arrays.copyOf(yValues, minLength), 0);
        assertThat(result).isNotEmpty();
    }
}
