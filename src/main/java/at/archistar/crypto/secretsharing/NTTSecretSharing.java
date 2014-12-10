package at.archistar.crypto.secretsharing;

import at.archistar.crypto.data.InvalidParametersException;
import at.archistar.crypto.data.Share;
import static at.archistar.crypto.data.Share.NTT_SHARE_SIZE;
import static at.archistar.crypto.data.Share.ORIGINAL_LENGTH;
import at.archistar.crypto.data.Share.ShareType;
import at.archistar.crypto.data.ShareFactory;
import at.archistar.crypto.decode.Decoder;
import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.decode.UnsolvableException;
import at.archistar.crypto.math.DynamicOutputEncoderConverter;
import at.archistar.crypto.math.EncodingConverter;
import at.archistar.crypto.math.GF;
import at.archistar.crypto.math.GFFactory;
import at.archistar.crypto.math.OutputEncoderConverter;
import at.archistar.crypto.math.ntt.AbstractNTT;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author andy
 */
abstract class NTTSecretSharing extends BaseSecretSharing {
    
    private final int generator;
    
    private final GF gf;
        
    private final AbstractNTT ntt;
    
    /** size in bytes of the NTT block (i.e. block that will be put into
     *  the ntt operation).
     */
    protected final int nttBlockLength = 256;
    
    private final int[] xValues;
    
    private final DecoderFactory decoderFactory;
    
    protected int shareSize = 0;
    
    protected int dataPerNTT = 0;
    
    public NTTSecretSharing(int n, int k, int generator,
                            GFFactory factory,
                            AbstractNTT ntt,
                            DecoderFactory decoderFactory) throws WeakSecurityException {
        
        super(n, k);
        
        if (k >= n) {
            throw new WeakSecurityException("k must be < n");
        }
        
        this.gf = factory.createHelper();
        
        if (nttBlockLength != (gf.getFieldSize() -1)) {
            throw new RuntimeException("impossible: GF(n) must equal NTT(n+1)");
        }
        
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
    
    protected abstract int[] encodeData(int tmp[], int[] data, int offset, int length);
    
    protected OutputEncoderConverter[] encode(int[] data) {
        
        int resultSize = ((data.length / dataPerNTT)+1)*shareSize;

        int[] encodedData;
        OutputEncoderConverter[] output = new OutputEncoderConverter[n];
        for (int i = 0; i < n; i++) {
            output[i] = new DynamicOutputEncoderConverter(resultSize, gf);
        }
        
        int offset = 0;
        encodedData = new int[nttBlockLength];
        for (int i = 0; i < data.length / dataPerNTT; i++, offset += dataPerNTT) {
            Arrays.fill(encodedData, 0);
            encodeData(encodedData, data, offset, dataPerNTT);
            ntt.inplaceNTT(encodedData, generator);
            
            for (int j = 0; j < n; j++) {
                output[j].append(encodedData, j * shareSize, shareSize);
            }
        }
        
        int rest = data.length % dataPerNTT;
        if (rest != 0) {
            encodedData = new int[nttBlockLength]; // initialized with 0
            encodeData(encodedData, data, offset, rest);
            ntt.inplaceNTT(encodedData, generator);
            
            for (int j = 0; j < n; j++) {
                output[j].append(encodedData, j * shareSize, shareSize);
            }            
        }
        
        return output;
    }
    
    @Override
    public Share[] share(byte[] data) {
        
        int[] dataInt = new int[data.length];
        for (int i = 0; i < data.length; i++) {
            dataInt[i] = (data[i] < 0) ? data[i]+256 : data[i];
        }
        
        OutputEncoderConverter[] encoded = encode(dataInt);
        Map<Byte, byte[]> metadata = new HashMap<>();
        metadata.put(NTT_SHARE_SIZE, ByteBuffer.allocate(4).putInt(shareSize).array());
        metadata.put(ORIGINAL_LENGTH, ByteBuffer.allocate(4).putInt(data.length).array());

        Share shares[] = new Share[n];
        for (int j = 0; j < n; j++) {
            try {
                shares[j] = ShareFactory.create(getShareType(), (byte)(j+1), encoded[j].getEncodedData(), metadata);
            } catch (InvalidParametersException ex) {
                throw new RuntimeException("impossible: cannot happen");
            }
        }
        return shares;
    }
    
    protected abstract ShareType getShareType();

    public int[] reconstruct(int[][] encoded, int[] xValues, int origLength) throws UnsolvableException {

        int minLength = (nttBlockLength/n)*k;
        
        /* expect a minimum of k parts */
        assert(encoded.length >= k);
        
        /* check that all parts are of the same length */
        int length = encoded[0].length;
        for (int i = 1; i < encoded.length; i++) {
            if (length != encoded[i].length) {
                throw new RuntimeException("impossible: encoded[" + i + "] length != encoded[0] length");
            }
        }
        
        int result[] = new int[origLength];
        int resultPos = 0;
        
        Decoder decoder = decoderFactory.createDecoder(xValues, minLength);

        int yValues[] = new int[minLength];
        for (int i = 0; i < length/shareSize; i++) {
            
            /* assume everything to be in the same order and xValues start with 1 */
            for (int j = 0; j < k; j++) {
              System.arraycopy(encoded[j], i*shareSize, yValues, j*shareSize, shareSize);
            }
            
            int[] tmp = decoder.decode(yValues, 0);
            
            int copyLength = dataPerNTT;
            if (copyLength > (origLength - resultPos)) {
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
        
        if (!validateShareCount(shares.length, k)) {
            throw new ReconstructionException();
        }
        
        int origLength = extractOriginalLength(shares);
        
        /* extract share count */
        int shareCount = extractShareCount(shares);
        
        /* create encoded array */
        int [][] encoded = new int[shares.length][];
        for (int i = 0; i < shares.length; i++) {
            EncodingConverter ec = new EncodingConverter(shares[i].getYValues(), gf);
            encoded[i] = ec.getDecodedData();
        }
        
        /* prepare xValues */
        int[] selectedXValues = setupXValues(shares, shareCount);
        
        try {
            int[] decoded = reconstruct(encoded, selectedXValues, origLength);
            
            byte[] result = new byte[origLength];
            for (int i = 0; i < result.length; i++) {
                result[i] = (byte)(decoded[i]);
            }
            return result;
        } catch (UnsolvableException ex) {
            throw new ReconstructionException(ex.getLocalizedMessage());
        }
    }
    
    protected int[] setupXValues(Share[] sshares, int shareSize) {
        int[] selectedXValues = new int[shareSize * sshares.length];
        for (int i = 0; i < sshares.length; i++) {
            int offset = (sshares[i].getId() -1) * shareSize;
            System.arraycopy(xValues, offset, selectedXValues, i*shareSize, shareSize);
        }
        return selectedXValues;
    }

    private int extractOriginalLength(Share[] shares) throws ReconstructionException {
        int origLength = shares[0].getMetadata(ORIGINAL_LENGTH);
        for (int i = 1; i < shares.length; i++) {
            if (shares[i].getMetadata(ORIGINAL_LENGTH) != origLength) {
                throw new ReconstructionException("originalLenghts are different");
            }
        }
        return origLength;
    }

    private int extractShareCount(Share[] shares) throws ReconstructionException {
        int shareCount = shares[0].getMetadata(NTT_SHARE_SIZE);
        for (int i = 1; i < shares.length; i++) {
            if (shares[i].getMetadata(NTT_SHARE_SIZE) != shareCount) {
                throw new ReconstructionException("shareCount are different");
            }
        }
        return shareCount;
    }
}
