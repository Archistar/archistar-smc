package at.archistar.crypto.secretsharing;

import at.archistar.crypto.data.BaseShare;
import at.archistar.crypto.data.ReedSolomonShare;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.decode.Decoder;
import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.decode.ErasureDecoder;
import at.archistar.crypto.decode.ErasureDecoderFactory;
import at.archistar.crypto.decode.UnsolvableException;
import at.archistar.crypto.exceptions.ReconstructionException;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.data.ByteUtils;
import at.archistar.crypto.data.InvalidParametersException;
import at.archistar.crypto.exceptions.ImpossibleException;
import at.archistar.crypto.math.GF;
import at.archistar.crypto.math.GFFactory;
import at.archistar.crypto.math.gf256.GF256Factory;
import at.archistar.crypto.math.gf257.GF257;
import java.util.Arrays;

/**
 * <p>This class implements the <i>Rabin IDS</i> (also called <i>Reed Solomon Code</i>) scheme.</p>
 * 
 * <p>For a detailed description of this scheme, see: 
 * <a href='http://en.wikipedia.org/wiki/Reed–Solomon_error_correction'>http://en.wikipedia.org/wiki/Reed–Solomon_error_correction</a></p>
 *  
 * <p><b>NOTE:</b> This scheme is not secure at all. It should only be used for sharing already encrypted 
 *                 data like for example how it is done in {@link KrawczykCSS}.</p>
 */
public class RabinIDS extends SecretSharing {
    private final DecoderFactory decoderFactory;
    
    private final GF gf;
    
    private static final GFFactory defaultGFFactory = new GF256Factory();
    
    /**
     * Constructor
     * <p>(applying {@link ErasureDecoder} as default reconstruction algorithm)</p>
     * 
     * @param n the number of shares to create
     * @param k the minimum number of shares required for reconstruction
     * @throws WeakSecurityException thrown if this scheme is not secure enough for the given parameters
     */
    public RabinIDS(int n, int k) throws WeakSecurityException {
        this(n, k, new ErasureDecoderFactory(defaultGFFactory), defaultGFFactory.createHelper());
    }
    
    /**
     * Constructor
     * 
     * @param n the number of shares to create
     * @param k the minimum number of shares required for reconstruction
     * @param decoderFactory the solving algorithm to use for reconstructing the secret
     * @throws WeakSecurityException thrown if this scheme is not secure enough for the given parameters
     */
    public RabinIDS(int n, int k, DecoderFactory decoderFactory) throws WeakSecurityException {
        this(n, k, decoderFactory, defaultGFFactory.createHelper());
    }
    
    /**
     * Constructor
     * 
     * @param n the number of shares to create
     * @param k the minimum number of shares required for reconstruction
     * @param decoderFactory the solving algorithm to use for reconstructing the secret
     * @param gf the field within which we will be doing all our computation
     * @throws WeakSecurityException thrown if this scheme is not secure enough for the given parameters
     */
    public RabinIDS(int n, int k, DecoderFactory decoderFactory, GF gf) throws WeakSecurityException {
        super(n, k);
        this.decoderFactory = decoderFactory;
        this.gf = gf;
    }

    @Override
    public Share[] share(byte[] data) {
        
        try {
            ReedSolomonShare shares[] = createReedSolomonShares(n, (data.length + k-1) / k, data.length);

            /* compute share values */
            int coeffs[] = new int[k];
            int fillPosition = 0;

            for (int i = 0; i < data.length; i += k) {
                for (int j = 0; j < k; j++) { // let k coefficients be the secret in this polynomial
                    if ((i + j) < data.length) {
                        coeffs[j] = data[i+j];
                    } else {
                        coeffs[j] = 0;
                    }
                }

                /* calculate the share a value for this byte for every share */
                for (int j = 0; j < n; j++) {
                    if (checkForZeros(coeffs)) { // skip evaluation in case all coefficients are 0
                        shares[j].getY()[fillPosition] = 0;
                    } else {
                        int value = gf.evaluateAt(coeffs, shares[j].getId());
                        
                        if (gf instanceof GF257 && value >= 0xff) {
                            assert(value >= 0 && value <= 256);
                            shares[j].setNewSize(shares[j].getY().length+1);
                            /* 0xff == -1 */
                            shares[j].getY()[fillPosition++] = (byte)-1;
                            System.err.println("set value:" + shares[j].getY()[fillPosition-1]);
                            shares[j].getY()[fillPosition] = (byte)(value - 0xff);
                            System.err.println("set value:" + shares[j].getY()[fillPosition]);
                        } else {
                            shares[j].getY()[fillPosition] = (byte)(value & 0xff);
                        }
                    }
                }
                fillPosition++;
            }

            return shares;
        } catch (InvalidParametersException ex) {
            throw new ImpossibleException("share failed: " + ex.getMessage());
        }
    }

    @Override
    public byte[] reconstruct(Share[] shares) throws ReconstructionException {
        if (!validateShareCount(shares.length, k)) {
            throw new ReconstructionException();
        }
        
        ReedSolomonShare[] rsshares = Arrays.copyOf(shares, shares.length, ReedSolomonShare[].class);
            
        int xValues[] = Arrays.copyOfRange(BaseShare.extractXVals(rsshares), 0, k); // we only need k x-values for reconstruction
        byte result[] = new byte[rsshares[0].getOriginalLength()];
        
        int index = 0;
            
        Decoder decoder = decoderFactory.createDecoder(xValues, k);
        for (int i = 0; i < rsshares[0].getY().length; i++) {
            int yValues[] = new int[k];
            for (int j = 0; j < k; j++) { // extract only k y-values (so we have k xy-pairs)
                 int tmp = rsshares[j].getY()[i];
                
                /* -1 == 0xff, I pray for an unsigned byte data type */
                if (gf instanceof GF257 && tmp == -1) {
                    assert(false);
                    yValues[j] = ((rsshares[j].getY()[++i] & 0xff) + 0xff) & 0xff;
                } else {
                    if (tmp < 0 && gf instanceof GF257) {
                        yValues[j] = tmp + 257;
                    } else if (tmp < 0) {
                        yValues[j] = tmp + 256;
                    } else {
                        yValues[j] = tmp;
                    }
                }
            }
                
            /* perform matrix-multiplication to compute the coefficients */
            try {
                int resultMatrix[] = decoder.decode(yValues, 0);
            
                for (int j = resultMatrix.length - 1; j >= 0 && index < rsshares[0].getOriginalLength(); j--) {
                    result[index++] = (byte)resultMatrix[resultMatrix.length - 1 - j];
                }
            } catch (UnsolvableException e) {
                throw new ReconstructionException();
            }
        }
        return result;
    }
    
    /**
     * Checks if the given array solely consists out of 0s.
     * @param a the array to check
     * @return true if yes; false otherwise
     */
    private static boolean checkForZeros(int[] a) {
        for (int i = 0; i < a.length; i++) {
            if (a[i] != 0) {
                return false;
            }
        }
        return true;
    }
    
    /**
     * Creates <i>n</i> ReedSolomonShares with the given share- and original-length.
     * 
     * @param n the number of ReedSolomonShare to create
     * @param shareLength the length of all shares
     * @return an array with the created shares
     */
    private static ReedSolomonShare[] createReedSolomonShares(int n, int shareLength, int originalLength) throws InvalidParametersException {
        ReedSolomonShare[] rsshares = new ReedSolomonShare[n];
        
        for (int i = 0; i < n; i++) {
            rsshares[i] = new ReedSolomonShare((byte) (i+1), new byte[shareLength], originalLength);
        }
        
        return rsshares;
    }
    
    @Override
    public String toString() {
        return "RabinIDS(" + n + "/" + k + ")";
    }
}
