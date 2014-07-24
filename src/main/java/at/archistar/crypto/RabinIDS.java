package at.archistar.crypto;

import at.archistar.crypto.data.ReedSolomonShare;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.exceptions.ReconstructionException;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.math.CustomMatrix;
import at.archistar.crypto.math.GF256Polynomial;
import at.archistar.crypto.math.PolyGF256;
import at.archistar.helper.ByteUtils;

/**
 * @author Elias Frantar <i>(improved Exception handline)</i>
 * @author Andreas Happe <andreashappe@snikt.net>
 * @author Fehrenbach Franca-Sofia
 * @author Thomas Loruenser <thomas.loruenser@ait.ac.at>
 */
public class RabinIDS extends SecretSharing {
	public RabinIDS(int n, int k) throws WeakSecurityException {
        super(n, k);
    }

    private boolean checkForZeros(int[] a) {
        for (int i = 0; i < a.length; i++) {
            if (a[i] != 0) {
                return false;
            }
        }
        return true;
    }

    @Override
    public Share[] share(byte[] data) {
        //Create shares
        ReedSolomonShare shares[] = new ReedSolomonShare[n];
        for (int i = 0; i < n; i++) {
            shares[i] = new ReedSolomonShare((byte) (i + 1), new byte[(data.length + k - 1) / k], data.length);
        }

        int a[] = new int[k];

        int fillPosition = 0;
        for (int i = 0; i < data.length; i += k) {

            //Let k coefficients be the secret in this polynomial
            for (int j = 0; j < k; j++) {
                if ((i + j) < data.length) {
                    a[j] = ByteUtils.toUnsignedByte(data[i + j]);
                    assert (a[j] >= 0 && a[j] <= 255);
                } else {
                    a[j] = 0;
                }
            }

            GF256Polynomial poly = new GF256Polynomial(a);

            //Calculate the share for this (source)byte for every share
            for (int j = 0; j < n; j++) {

                if (checkForZeros(a)) {
                    System.err.println("all a coefficients are zero");
                    System.err.println("i: " + i + " data.length: " + data.length);
                    shares[j].getY()[fillPosition] = 0;
                } else {
                    shares[j].getY()[fillPosition] = (byte) (poly.evaluateAt(shares[j].getId()));
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
    		ReedSolomonShare[] rsshares = safeCast(shares); // we need access to the fields of ReedSolomonShare
    		
	        int xValues[] = new int[k];
	        byte result[] = new byte[rsshares[0].getOriginalLength()];
	
	        for (int i = 0; i < k; i++) {
	            xValues[i] = rsshares[i].getId();
	        }
	
	        int w = 0;
	
	        CustomMatrix decodeMatrix = PolyGF256.erasureDecodePrepare(xValues);
	
	        for (int i = 0; i < rsshares[0].getY().length; i++) {
	
	        	int yValues[] = new int[k];
	            for (int j = 0; j < k; j++) {
	            	yValues[j] = ByteUtils.toUnsignedByte(rsshares[j].getY()[i]);
	            }
	
	            if (checkForZeros(yValues)) {
	            	for (int x = 0; x < k && w < result.length; x++) {
	            		result[w++] = 0;
	                }
	           } else {
	                int resultMatrix[] = decodeMatrix.rightMultiply(yValues);
	
	                for (int j = resultMatrix.length - 1; j >= 0 && w < rsshares[0].getOriginalLength(); j--) {
	                	int element = resultMatrix[resultMatrix.length - 1 - j];
	                    result[w++] = (byte) (element & 0xFF);
	                }
	           }
	        }
	        return result;
    	} catch (Exception e) { // if anything goes wrong during reconstruction, throw a ReconstructionException
    		throw new ReconstructionException();
    	}
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
