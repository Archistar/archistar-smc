package at.archistar.crypto.secretsharing;

import at.archistar.crypto.data.BaseShare;
import at.archistar.crypto.data.InvalidParametersException;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.decode.Decoder;
import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.decode.UnsolvableException;
import at.archistar.crypto.exceptions.ReconstructionException;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.math.DynamicOutputEncoderConverter;
import at.archistar.crypto.math.EncodingConverter;
import at.archistar.crypto.math.GF;
import at.archistar.crypto.math.OutputEncoderConverter;
import at.archistar.crypto.math.StaticOutputEncoderConverter;
import at.archistar.crypto.math.gf257.GF257;
import static at.archistar.crypto.secretsharing.BaseSecretSharing.validateShareCount;
import java.util.Arrays;

/**
 *
 * @author andy
 */
public abstract class GeometricSecretSharing extends BaseSecretSharing {
    
    private final DecoderFactory decoderFactory;
    
    protected final GF gf;
    
    protected int dataPerRound = 1;
    
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
    }
    
    protected abstract void encodeData(int coeffs[], byte[] data, int offset, int length);

    @Override
    public Share[] share(byte[] data) {
        
        int xValues[] = new int[n];
        for (int i = 0; i < n; i++) {
            xValues[i] = i+1;
        }
        
        try {
            /* compute share values */
            int coeffs[] = new int[k];
            OutputEncoderConverter output[] = new OutputEncoderConverter[n];
            for (int i = 0; i < n; i++) {
                if (gf instanceof GF257) {
                    output[i] = new DynamicOutputEncoderConverter(data.length, gf);
                } else {                
                    output[i] = new StaticOutputEncoderConverter(data.length);
                }
            }

            for (int i = 0; i < data.length; i += dataPerRound) {
                
                encodeData(coeffs, data, i, dataPerRound);

                /* calculate the share a value for this byte for every share */
                for (int j = 0; j < n; j++) {
                    // skip evaluation in case all coefficients are 0
                    output[j].append(checkForZeros(coeffs) ? 0 : gf.evaluateAt(coeffs, xValues[j]));
                }
            }
            
            return createShares(xValues, output, data.length);
        } catch (InvalidParametersException ex) {
            throw new RuntimeException("impossible: share failed: " + ex.getMessage());
        }
    }
    
    protected abstract Share[] createShares(int[] xValues, OutputEncoderConverter[] results, int originalLength) throws InvalidParametersException;

    protected abstract EncodingConverter[] prepareInput(Share[] shares);
    
    protected abstract int retrieveInputLength(Share[] shares);
    
    @Override
    public byte[] reconstruct(Share[] shares) throws ReconstructionException {
        if (!validateShareCount(shares.length, k)) {
            throw new ReconstructionException();
        }
        
        EncodingConverter input[] = prepareInput(shares);
        
        int originalLength = retrieveInputLength(shares);
        byte result[] = new byte[originalLength];
        int xValues[] = Arrays.copyOfRange(BaseShare.extractXVals(shares), 0, k); // we only need k x-values for reconstruction
            
        Decoder decoder = decoderFactory.createDecoder(xValues, k);
        int posResult = 0;
        while (posResult < originalLength) {
            int yValues[] = new int[k];
            for (int j = 0; j < k; j++) { // extract only k y-values (so we have k xy-pairs)
                yValues[j] = input[j].readNext();
            }
                
            /* perform matrix-multiplication to compute the coefficients */
            try {
                int resultMatrix[] = decoder.decode(yValues, 0);
                posResult = decodeData(resultMatrix, originalLength, result, posResult);
            } catch (UnsolvableException e) {
                throw new ReconstructionException();
            }
        }
        return result;
    }
    
    protected abstract int decodeData(int[] encoded, int originalLength, byte[] result, int offset);
    
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

}
