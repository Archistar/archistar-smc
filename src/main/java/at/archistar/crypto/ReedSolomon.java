package at.archistar.crypto;

import helper.ShareHelper;
import helper.ByteUtils;

import java.util.Arrays;

import at.archistar.crypto.data.Share;
import at.archistar.crypto.decode.ErasureDecoder;
import at.archistar.crypto.exceptions.ReconstructionException;
import at.archistar.crypto.math.GF256Polynomial;

/**
 * <p>This class implements the <i>Reed-Solomon-Code</i> scheme.</p>
 * 
 * <p>For a detailed description of this scheme, see: 
 * <a href='http://en.wikipedia.org/wiki/Reed–Solomon_error_correction'>http://en.wikipedia.org/wiki/Reed–Solomon_error_correction</a></p>
 *  
 * <p><b>NOTE:</b> This scheme is not secure at all. It should only be used for sharing already encrypted 
 * 				   data like for example how it is done in {@link KrawczykCSS}.</p>
 * 
 * @author Elias Frantar <i>(code refactored, documentation added)</i>
 * @author Andreas Happe <andreashappe@snikt.net>
 * @author Fehrenbach Franca-Sofia
 * @author Thomas Loruenser <thomas.loruenser@ait.ac.at>
 * 
 * @version 2014-7-15
 */
public class ReedSolomon extends SecretSharing {
    
	/**
     * Constructor
     * (Applying the default settings for the decoder: {@link ErasureDecoder})
     * 
     * @param n the number of shares
     * @param k the minimum number of shares required for reconstruction
     */
    public ReedSolomon(int n, int k) {
        this.n = n;
        this.k = k;
        
        solver = new ErasureDecoder();
    }

    @Override
    public Share[] share(byte[] data) {
        Share shares[] = Share.createReedSolomonShares(n, (data.length + k-1) / k, data.length);

        /* compute share values */
        int coeffs[] = new int[k];
        int fillPosition = 0;
        
        for (int i = 0; i < data.length; i += k) {
            for (int j = 0; j < k; j++) // let k coefficients be the secret in this polynomial
                if ((i + j) < data.length)
                    coeffs[j] = ByteUtils.toUnsignedByte(data[i + j]);
                else
                    coeffs[j] = 0;

            GF256Polynomial poly = new GF256Polynomial(coeffs);

            /* calculate the share a value for this byte for every share */
            for (int j = 0; j < n; j++)
               shares[j].setY(fillPosition, (byte)poly.evaluateAt(shares[j].getX()));
            fillPosition++;
        }
        
        return shares;
    }

    @Override
    public byte[] reconstruct(Share[] shares) throws ReconstructionException {
    	if(shares.length < k)
    		throw new ReconstructionException();
    	
    	try {
	    	int xValues[] = Arrays.copyOfRange(ShareHelper.extractXVals(shares), 0, k); // we only need k x-values for reconstruction
		    byte result[] = new byte[shares[0].getOriginalLength()];
		
		    int index = 0;
		    
		    solver.prepare(xValues);
	
	        for (int i = 0; i < shares[0].getY().length; i++) {
	        	int yValues[] = new int[k];
	        	
	            for (int j = 0; j < k; j++) // extract only k y-values (so we have k xy-pairs)
	            	yValues[j] = shares[j].getY(i);
	
	            /* perform matrix-multiplication to compute the coefficients */
	            int resultMatrix[] = solver.solve(yValues);
	            for (int j = resultMatrix.length - 1; j >= 0 && index < shares[0].getOriginalLength(); j--)
	            	result[index++] = (byte) resultMatrix[resultMatrix.length - 1 - j];
		    }
        
	        return result;
    	}
    	catch(Exception e) {
    		throw new ReconstructionException();
    	}
    }
}