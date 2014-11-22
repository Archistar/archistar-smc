package at.archistar.crypto.secretsharing;

import at.archistar.crypto.decode.Decoder;
import at.archistar.crypto.decode.UnsolvableException;
import at.archistar.crypto.exceptions.ImpossibleException;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.math.GF;
import at.archistar.crypto.math.GFFactory;
import at.archistar.crypto.math.ntt.AbstractNTT;
import at.archistar.crypto.random.RandomSource;
import org.bouncycastle.util.Arrays;

/**
 * @author andy
 */
public class NTTShamirPSS {
    
    private final int n;
    
    private final int k;
    
    private final int generator;
    
    private final GFFactory factory;
    
    private final GF gf;
    
    private final int blockCount;
    
    private final RandomSource rng;
    
    private final AbstractNTT ntt;
    
    /** size in bytes of the NTT block (i.e. block that will be put into
     *  the ntt operation).
     */
    private final int NTTBlockLength = 256;
    
    private final int[] xValues;
    
    private final Decoder decoder;
    
    public NTTShamirPSS(int n, int k, int generator, GFFactory factory, RandomSource rng, AbstractNTT ntt, Decoder decoder) throws WeakSecurityException {
        this.n = n;
        this.k = k;
        
        if (k >= n) {
            throw new WeakSecurityException("k must be < n");
        }
        
        this.factory = factory;
        this.gf = factory.createHelper();
        
        if (NTTBlockLength != (gf.getFieldSize() -1 )) {
            throw new ImpossibleException("GF(n) must equal NTT(n+1)");
        }
        
        /** how much (in bytes) can we fit per share (n shares must fit into
          * a NTTBlock)
          */
        blockCount = NTTBlockLength / n;
        
        this.rng = rng;
        this.ntt = ntt;
        
        this.generator = generator;
        this.xValues = prepareXValuesFor(generator, gf);
        this.decoder = decoder;
    }
    
    /**
     * prepare all possible xValues
     */
    public static int[] prepareXValuesFor(int generator, GF gf) {
         
        int[] tmp= new int[256];
        
        tmp[0] = 1;
        for (int i = 1; i < 256; i++) {
            tmp[i] = gf.mult(tmp[i-1], generator);
        }
        return tmp;
    }
    
    protected int[] encodeData(int[] data, int offset, int length) {
        int[] tmp = new int[NTTBlockLength]; // initialized with 0

        System.arraycopy(data, offset, tmp, 0, length);

        /* (k-1) -- shamir uses 1 byte secret and (k-1) byte randomness */
        int[] random = new int[length * (k - 1)];
        rng.fillBytesAsInts(random);

        System.arraycopy(random, 0, tmp, blockCount, random.length);
        
        return tmp;
    }
    
    public int[][] encode(int[] data) {
        
        int resultSize = ((data.length / blockCount)+1)*blockCount;
                
        int[][] output = new int[n][resultSize];
        for (int i = 0; i < (data.length / blockCount)+1; i++) {
            
            int copyLength = (blockCount * (i+1) < data.length) ? blockCount : (data.length % blockCount);
            int offset = i * blockCount;
            
            int[] encodedData = encodeData(data, offset, copyLength);
            int[] conv = ntt.ntt(encodedData, generator);
            
            for (int j = 0; j < n; j++) {
                System.arraycopy(conv, j*blockCount, output[j], i*blockCount, blockCount);
            }
        }
        return output;        
    }
    
    public int[] reconstruct(int[][] encoded, int[] xValues, int origLength) throws UnsolvableException {

        int minLength = (NTTBlockLength/n)*k;
        
        /* expect a minimum of k parts */
        assert(encoded.length >= k);
        
        /* check that all parts are of the same length */
        int length = encoded[0].length;
        for (int i = 1; i < encoded.length; i++) {
            if (length != encoded[i].length) {
                throw new ImpossibleException("encoded[" + i + "] length != encoded[0] length");
            }
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
            
            System.arraycopy(tmp, 0, result, resultPos, copyLength);
            resultPos += copyLength;
        }
        
        if (origLength != result.length) {
            result = Arrays.copyOf(result, origLength);
        }
        return result;
    }
}
