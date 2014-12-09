package at.archistar.crypto.secretsharing;

import at.archistar.crypto.data.InvalidParametersException;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.decode.Decoder;
import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.decode.UnsolvableException;
import at.archistar.crypto.math.DynamicOutputEncoderConverter;
import at.archistar.crypto.math.EncodingConverter;
import at.archistar.crypto.math.GF;
import at.archistar.crypto.math.OutputEncoderConverter;
import at.archistar.crypto.math.StaticOutputEncoderConverter;
import at.archistar.crypto.math.gf257.GF257;
import static at.archistar.crypto.secretsharing.BaseSecretSharing.validateShareCount;

/**
 * <p>this contains basic functionality utilized by RabinIDS and ShamirPSS.</p>
 * 
 * <p>Secret-sharing can be seen as solving an overdetermined Equation. Given an
 * equation of degree k a minimum of k points are needed to solve the equation.
 * I.e. for degree 3 there's an equation y = a0*x^0 + a1*x^1 + a2*x^2. We need
 * 3 (x,y) pairs to determine [a0, a1, a2]. Secret-sharing schemes deriving from
 * this class utilize this: for a k/n sharing scheme we're creating a equation
 * of degree k (so k (x,y) pairs will be needed to solve the equation) and fill
 * in [a0.. a_k] with data. By setting in random x-Values we calculate n (x,y)
 * pairs -- those are the shares that will be distributed between participants.</p>
 */
public abstract class GeometricSecretSharing extends BaseSecretSharing {
    
    private final DecoderFactory decoderFactory;
    
    /** the mathematical field all operations are performed in */
    protected final GF gf;
    
    /** this describes how many (secret) original data bytes are encoded per
     * encryption round -- this is supposed to be overwritten by subclasses
     */
    protected int dataPerRound = 1;
    
    private final int[] xValues;
    
    /**
     * Constructor
     * 
     * @param n the number of shares to create
     * @param k the minimum number of shares required for reconstruction
     * @param decoderFactory the solving algorithm to use for reconstructing the secret
     * @param gf the field within which we will be doing all our computation
     * @throws WeakSecurityException thrown if this scheme is not secure enough for the given parameters
     */
    public GeometricSecretSharing(int n, int k, DecoderFactory decoderFactory, GF gf) throws WeakSecurityException {
        super(n, k);
        this.decoderFactory = decoderFactory;
        this.gf = gf;
        
        xValues = new int[n];
        for (int i = 0; i < n; i++) {
            xValues[i] = i+1;
        }
    }
    
    /**
     * This method should prepare the coefficients for our equation.
     * 
     * @param coeffs the resulting coefficients
     * @param data the original data. For performance reasons the same data
     *             array is passed for multiple encoding rounds and the current
     *             data is determined by accessing data[offset .. (offset+length)]
     * @param offset current position within the data array
     * @param length how much (original) data should be encoded within coeffs
     */
    protected abstract void encodeData(int coeffs[], byte[] data, int offset, int length);
    
    /**
     * Creates <i>n</i> secret shares for the given data where <i>k</i> shares are required for reconstruction. 
     * @param data the data to share secretly
     * @param output n buffers where the output will be stored
     */
    public void share(OutputEncoderConverter output[], byte[] data) {
        assert(output.length == n);
        int coeffs[] = new int[k];
        
        for (int i = 0; i < data.length; i += dataPerRound) {
            encodeData(coeffs, data, i, dataPerRound);

            /* calculate the share a value for this byte for every share */
            for (int j = 0; j < n; j++) {
                // skip evaluation in case all coefficients are 0
                output[j].append(checkForZeros(coeffs) ? 0 : gf.evaluateAt(coeffs, xValues[j]));
            }
        }
    }

    /**
     * Creates <i>n</i> secret shares for the given data where <i>k</i> shares
     * are required for reconstruction. (n, k should have been previously initialized)
     * 
     * @param data the data to share secretly
     * @return the n different secret shares for the given data
     */
    @Override
    public Share[] share(byte[] data) {
        try {
            OutputEncoderConverter output[] = new OutputEncoderConverter[n];
            for (int i = 0; i < n; i++) {
                if (gf instanceof GF257) {
                    output[i] = new DynamicOutputEncoderConverter(data.length, gf);
                } else {                
                    output[i] = new StaticOutputEncoderConverter(data.length);
                }
            }
            
            share(output, data);

            return createShares(xValues, output, data.length);
        } catch (InvalidParametersException ex) {
            throw new RuntimeException("impossible: share failed: " + ex.getMessage());
        }
    }
    
    /**
     * After data was encoded algorithm-specific share must be created. As the
     * generic implementation does not know, which fields to fill (or which meta
     * data is needed) this task was delegated to the implementing sub-class.
     * 
     * @param xValues the used xValues
     * @param results output buffer with the expected body (of the new share)
     * @param originalLength the original data length (of the secret)
     * @return Array of created shares
     * @throws InvalidParametersException if no valid share was build
     */
    protected abstract Share[] createShares(int[] xValues,
                                            OutputEncoderConverter[] results,
                                            int originalLength) throws InvalidParametersException;
    
    /**
     * Calculates and retrieves the length of the original (now encrypted) data.
     * This varies between algorithms, i.e. with ShamirPSS the original length
     * is the same as the share's body length. With RabinIDS the orignial length
     * must be stored as meta data as it cannot be automatically derived from the
     * body's length
     * 
     * @param shares all input shares
     * @return  original length of the encrypted secret data
     */
    protected abstract int retrieveInputLength(Share[] shares);

    /**
     * Attempts to reconstruct the secret from the given input stream.
     * This will fail if there are fewer than k (previously initialized) valid shares.
     * 
     * @param input the body of the share's to reconstruct the secret from
     * @param xValues the xValues (from the shares)
     * @param originalLength the secret's length -- this might be need to recognize padding
     * @return the reconstructed secret
     * @throws ReconstructionException thrown if the reconstruction failed
     */
    public byte[] reconstruct(EncodingConverter[] input, int[] xValues, int originalLength) throws ReconstructionException {
        Decoder decoder = decoderFactory.createDecoder(xValues, k);
        byte result[] = new byte[originalLength];
        int yValues[] = new int[k];
        int resultMatrix[] = new int[k];

        int posResult = 0;
        while (posResult < originalLength) {
            for (int j = 0; j < k; j++) { // extract only k y-values (so we have k xy-pairs)
                yValues[j] = input[j].readNext();
            }
                
            /* perform matrix-multiplication to compute the coefficients */
            try {
                decoder.decodeUnsafe(resultMatrix, yValues, 0);
                posResult = decodeData(resultMatrix, originalLength, result, posResult);
            } catch (UnsolvableException e) {
                throw new ReconstructionException();
            }
        }
        return result;
    }
    
    /**
     * Attempts to reconstruct the secret from the given shares.<br>
     * This will fail if there are fewer than k (previously initialized) valid shares.
     * 
     * @param shares the shares to reconstruct the secret from
     * @return the reconstructed secret
     * @throws ReconstructionException thrown if the reconstruction failed
     */
    @Override
    public byte[] reconstruct(Share[] shares) throws ReconstructionException {
        if (!validateShareCount(shares.length, k)) {
            throw new ReconstructionException();
        }
        
        EncodingConverter input[] = new EncodingConverter[shares.length];
        for (int i = 0; i < shares.length; i++) {
            input[i] = new EncodingConverter(shares[i].getYValues(), gf);
        }
        
        int originalLength = retrieveInputLength(shares);
        // we only need k x-values for reconstruction
        int xTmpValues[] = extractXVals(shares, k);
        
        return reconstruct(input, xTmpValues, originalLength);
    }
    
    /**
     * While reconstructing the original secret the encrypted data is passed on
     * to an equation solver. The result of this operation is passed on to this
     * method which should extract the original data from the solver's result.
     * 
     * @param encoded original data that was put into the equation during sharing
     * @param originalLength how long was the original data. This is needed as
     *                       some algorithms (i.e. RabinIDS) utilize padding if
     *                       the last data block wasn't fully filled.
     * @param result an array where the resulting data should be stored in. The
     *               concrete position within this array is given by offset
     * @param offset current position within result array
     * @return amount (in byte) of retrieved original data (used to calculate
     *         new offset)
     */
    protected abstract int decodeData(int[] encoded, int originalLength, byte[] result, int offset);
    
    /**
     * Checks if the given array solely consists out of 0s.
     * @param a the array to check
     * @return true if yes; false otherwise
     */
    private static boolean checkForZeros(int[] a) {
        for (int i : a) {
            if (i != 0) {
                return false;
            }
        }
        return true;
    }
    
    /**
     * Extracts k x-values from the given shares.
     * 
     * @param shares the shares to extract the x-values from
     * @param k how many xValues do we want?
     * @return an array with all x-values from the given shares (in same order as the given Share[])
     */
    public static int[] extractXVals(Share[] shares, int k) {
        int[] x = new int[k];
        
        for (int i = 0; i < k; i++) {
            x[i] = shares[i].getId();
        }
        
        return x;
    }
}
