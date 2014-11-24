package at.archistar.crypto.secretsharing;

import at.archistar.crypto.data.InvalidParametersException;
import at.archistar.crypto.data.NTTShamirShare;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.decode.Decoder;
import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.decode.UnsolvableException;
import at.archistar.crypto.exceptions.ImpossibleException;
import at.archistar.crypto.exceptions.ReconstructionException;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.math.EncodingConverter;
import at.archistar.crypto.math.GF;
import at.archistar.crypto.math.GFFactory;
import at.archistar.crypto.math.ntt.AbstractNTT;
import at.archistar.crypto.random.RandomSource;
import java.util.Arrays;

/**
 * @author andy
 */
public class NTTShamirPSS extends SecretSharing {
    
    private final int generator;
    
    private final GFFactory factory;
    
    private final GF gf;
    
    private final int blockCount;
    
    private final RandomSource rng;
    
    private final AbstractNTT ntt;
    
    /** size in bytes of the NTT block (i.e. block that will be put into
     *  the ntt operation).
     */
    private final int nttBlockLength = 256;
    
    private final int[] xValues;
    
    private final DecoderFactory decoderFactory;
    
    public NTTShamirPSS(int n, int k, int generator, GFFactory factory, RandomSource rng, AbstractNTT ntt, DecoderFactory decoderFactory) throws WeakSecurityException {
        
        super(n, k);
        
        if (k >= n) {
            throw new WeakSecurityException("k must be < n");
        }
        
        this.factory = factory;
        this.gf = factory.createHelper();
        
        if (nttBlockLength != (gf.getFieldSize() -1)) {
            throw new ImpossibleException("GF(n) must equal NTT(n+1)");
        }
        
        /** how much (in bytes) can we fit per share (n shares must fit into
          * a NTTBlock)
          */
        blockCount = nttBlockLength / n;
        
        this.rng = rng;
        this.ntt = ntt;
        
        this.generator = generator;
        this.xValues = prepareXValuesFor(generator, gf);
        this.decoderFactory = decoderFactory;
    }
    
    /**
     * prepare all possible xValues
     * @param generator the generator to be sued
     * @param gf within which gf should we compute the xValues
     * @return an array of possible xValues
     */
    public static int[] prepareXValuesFor(int generator, GF gf) {
         
        int[] tmp = new int[256];
        
        tmp[0] = 1;
        for (int i = 1; i < 256; i++) {
            tmp[i] = gf.mult(tmp[i-1], generator);
        }
        return tmp;
    }
    
    protected int[] encodeData(int tmp[], int[] data, int offset, int length) {
        System.arraycopy(data, offset, tmp, 0, length);

        /* (k-1) -- shamir uses 1 byte secret and (k-1) byte randomness */
        int[] random = new int[length * (k - 1)];
        rng.fillBytesAsInts(random);

        System.arraycopy(random, 0, tmp, blockCount, random.length);
        
        return tmp;
    }
    
    protected int[][] encode(int[] data) {
        
        int resultSize = ((data.length / blockCount)+1)*blockCount;

        int[] encodedData = new int[nttBlockLength]; // initialized with 0
        int[][] output = new int[n][resultSize];
        
        for (int i = 0; i < (data.length / blockCount)+1; i++) {
            
            int copyLength = (blockCount * (i+1) < data.length) ? blockCount : (data.length % blockCount);
            int offset = i * blockCount;
            
            encodeData(encodedData, data, offset, copyLength);
            int[] conv = ntt.ntt(encodedData, generator);
            
            for (int j = 0; j < n; j++) {
                System.arraycopy(conv, j*blockCount, output[j], i*blockCount, blockCount);
            }
        }
        return output;
    }
    
    /* TODO: encode gf(257) -> byte ! */
    @Override
    public Share[] share(byte[] data) {
        int[] dataInt = new int[data.length];
        for (int i = 0; i < data.length; i++) {
            dataInt[i] = (data[i] < 0) ? data[i]+256 : data[i];
        }
        
        int[][] encoded = encode(dataInt);
        NTTShamirShare shares[] = new NTTShamirShare[n];
        
        try {
            for (int j = 0; j < n; j++) {
                byte[] result = EncodingConverter.encodeAll(encoded[j], gf);
                shares[j] = new NTTShamirShare((byte)(j+1), result, blockCount, data.length);
            }
        } catch (InvalidParametersException ex) {
            throw new ImpossibleException("sharing failed (" + ex.getMessage() + ")");
        }
        return shares;
    }

    
    public int[] reconstruct(int[][] encoded, int[] xValues, int origLength) throws UnsolvableException {

        int minLength = (nttBlockLength/n)*k;
        
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
        
        Decoder decoder = decoderFactory.createDecoder(xValues, minLength);

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

    @Override
    public byte[] reconstruct(Share[] shares) throws ReconstructionException {
        
        /* you cannot cast arrays to arrays of subtype in java7 */
        NTTShamirShare[] sshares = Arrays.copyOf(shares, shares.length, NTTShamirShare[].class); // we need access to the inner fields
        
        /* extract original length */
        int origLength = sshares[0].getOriginalLength();
        for (int i = 1; i < sshares.length; i++) {
            if (sshares[i].getOriginalLength() != origLength) {
                throw new ReconstructionException("originalLenghts are different");
            }
        }
        
        /* extract share count */
        int shareCount = sshares[0].getShareCount();
        for (int i = 1; i < sshares.length; i++) {
            if (sshares[i].getShareCount() != shareCount) {
                throw new ReconstructionException("shareCount are different");
            }
        }
        
        /* create encoded array */
        int [][] encoded = new int[sshares.length][];
        for (int i = 0; i < sshares.length; i++) {
            EncodingConverter ec = new EncodingConverter(sshares[i].getY(), gf);
            encoded[i] = ec.getDecodedData();
        }
        
        /* prepare xValues */
        int[] selectedXValues = new int[shareCount * sshares.length];
        for (int i = 0; i < sshares.length; i++) {
            int offset = (sshares[i].getId() -1) * shareCount;
            System.arraycopy(xValues, offset, selectedXValues, i*shareCount, shareCount);
        }
        
        try {
            int[] decoded = reconstruct(encoded, selectedXValues, origLength);
            
            byte[] result = new byte[decoded.length];
            for (int i = 0; i < result.length; i++) {
                result[i] = (byte)(decoded[i]);
            }
            return result;
        } catch (UnsolvableException ex) {
            throw new ReconstructionException(ex.getLocalizedMessage());
        }
    }
}
