package at.archistar.crypto;

import java.util.Arrays;

import at.archistar.crypto.data.ReedSolomonShare;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.decode.ErasureDecoder;
import at.archistar.crypto.decode.PolySolver;
import at.archistar.crypto.exceptions.ReconstructionException;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.math.GF256Polynomial;
import at.archistar.helper.ByteUtils;
import at.archistar.helper.ShareHelper;

/**
 * <p>This class implements the <i>Rabin IDS</i> (also called <i>Reed Solomon Code</i>) scheme.</p>
 * 
 * <p>For a detailed description of this scheme, see: 
 * <a href='http://en.wikipedia.org/wiki/Reed–Solomon_error_correction'>http://en.wikipedia.org/wiki/Reed–Solomon_error_correction</a></p>
 *  
 * <p><b>NOTE:</b> This scheme is not secure at all. It should only be used for sharing already encrypted 
 *                 data like for example how it is done in {@link KrawczykCSS}.</p>
 * 
 * @author Elias Frantar <i>(code refactored, documentation added)</i>
 * @author Andreas Happe <andreashappe@snikt.net>
 * @author Fehrenbach Franca-Sofia
 * @author Thomas Loruenser <thomas.loruenser@ait.ac.at>
 * 
 * @version 2014-7-25
 */
public class RabinIDS extends SecretSharing {
	private PolySolver solver;
	
	/**
     * Constructor
     * <p>(applying {@link ErasureDecoder} as default reconstruction algorithm)</p>
     * 
     * @param n the number of shares to create
     * @param k the minimum number of shares required for reconstruction
	 * @throws WeakSecurityException thrown if this scheme is not secure enough for the given parameters
     */
	public RabinIDS(int n, int k) throws WeakSecurityException {
        this(n, k, new ErasureDecoder());
    }
	/**
     * Constructor
     * 
     * @param n the number of shares to create
     * @param k the minimum number of shares required for reconstruction
     * @param solver the solving algorithm to use for reconstructing the secret
     * @throws WeakSecurityException thrown if this scheme is not secure enough for the given parameters
     */
	public RabinIDS(int n, int k, PolySolver solver) throws WeakSecurityException {
		super(n, k);
		
		this.solver = solver;
	}

    @Override
    public Share[] share(byte[] data) {
        ReedSolomonShare shares[] = ShareHelper.createReedSolomonShares(n, (data.length + k-1) / k, data.length);

        /* compute share values */
        int coeffs[] = new int[k];
        int fillPosition = 0;
        
        for (int i = 0; i < data.length; i += k) {
            for (int j = 0; j < k; j++) { // let k coefficients be the secret in this polynomial
                if ((i + j) < data.length) {
                    coeffs[j] = ByteUtils.toUnsignedByte(data[i + j]);
                } else {
                    coeffs[j] = 0;
                }
            }

            GF256Polynomial poly = new GF256Polynomial(coeffs);

            /* calculate the share a value for this byte for every share */
            for (int j = 0; j < n; j++) {
                if (checkForZeros(coeffs)) { // skip evaluation in case all coefficients are 0
                    shares[j].getY()[fillPosition] = 0;
                } else {
                    shares[j].getY()[fillPosition] = (byte)poly.evaluateAt(shares[j].getId());
                }
            }
            fillPosition++;
        }
        
        return shares;
    }

    @Override
    public byte[] reconstruct(Share[] shares) throws ReconstructionException {
    	if (!validateShareCount(shares.length, k)) {
    		throw new ReconstructionException();
    	}
    	
    	try {
    	    ReedSolomonShare[] rsshares = safeCast(shares); // we need access to the inner fields
            
    	    int xValues[] = Arrays.copyOfRange(ShareHelper.extractXVals(rsshares), 0, k); // we only need k x-values for reconstruction
            byte result[] = new byte[rsshares[0].getOriginalLength()];
        
            int index = 0;
            
            solver.prepare(xValues);
    
            for (int i = 0; i < rsshares[0].getY().length; i++) {
                int yValues[] = new int[k];
                
                for (int j = 0; j < k; j++) { // extract only k y-values (so we have k xy-pairs)
                    yValues[j] = ByteUtils.toUnsignedByte(rsshares[j].getY()[i]);
                }
                
                /* perform matrix-multiplication to compute the coefficients */
                int resultMatrix[] = solver.solve(yValues);
                for (int j = resultMatrix.length - 1; j >= 0 && index < rsshares[0].getOriginalLength(); j--) {
                    result[index++] = (byte) resultMatrix[resultMatrix.length - 1 - j];
                }
            }
        
            return result;
        } catch(Exception e) {
            e.printStackTrace();
            throw new ReconstructionException();
        }
    }
    
    /**
     * Checks if the given array solely consists out of 0s.
     * @param a the array to check
     * @return true if yes; false otherwise
     */
    private boolean checkForZeros(int[] a) {
        for (int i = 0; i < a.length; i++) {
            if (a[i] != 0) {
                return false;
            }
        }
        return true;
    }
    
    /**
     * Converts the Share[] to a ReedSolomonShare[] by casting each element individually.
     * 
     * @param shares the shares to cast
     * @return the given Share[] as ReedSolomonShare[]
     * @throws ClassCastException if the Share[] did not (only) contain ReedSolomonShares
     */
    private ReedSolomonShare[] safeCast(Share[] shares) {
    	ReedSolomonShare[] rsshares = new ReedSolomonShare[shares.length];
    	
    	for (int i = 0; i < shares.length; i++) {
    		rsshares[i] = (ReedSolomonShare) shares[i];
    	}
    	
    	return rsshares;
    }
}
