package at.archistar.crypto;

import de.flexiprovider.common.math.codingtheory.PolynomialGF2mSmallM;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.math.CustomMatrix;
import at.archistar.crypto.math.GF256;
import at.archistar.crypto.math.PolyGF256;
import at.archistar.crypto.math.ReconstructionException;
import at.archistar.helper.ImpossibleException;

/**
 * @author Andreas Happe <andreashappe@snikt.net>
 * @author Fehrenbach Franca-Sofia
 * @author Thomas Loruenser <thomas.loruenser@ait.ac.at>
 */
public class RabinIDS implements SecretSharing {
	
	private final int n;
	
	private final int k;
	
	public RabinIDS(int n, int k) {
		this.n = n;
		this.k = k;
	}


	private boolean checkForZeros(int[] a) {
          for(int i=0; i < a.length;i ++) {
            if (a[i] != 0 ) {
              return false;
            }
          }
          return true;
	}

	@Override
	public Share[] share(byte[] data) throws WeakSecurityException {
		
		if(k < 2) {
			throw new WeakSecurityException();
		}
		
		//Create shares
		Share shares[] = new Share[n];
		for(int i=0; i < n; i++) {
			shares[i] = new Share(i+1, (data.length + k-1)/k, data.length, Share.Type.REED_SOLOMON);
		}
		
		int a[] = new int[k];		
		
		int fillPosition = 0;
		for(int i=0; i < data.length; i+=k) { 
			
			//Let k coefficients be the secret in this polynomial
			for(int j=0; j < k; j++) {
				if((i+j) < data.length) {
					a[j] = (data[i+j] < 0) ? data[i+j]+256 : data[i+j];
					assert(a[j] >= 0 && a[j] <= 255);
				} else {
					a[j] = 0;
				}
			}

			PolynomialGF2mSmallM poly = new PolynomialGF2mSmallM(GF256.gf256, a);
			
			//Calculate the share for this (source)byte for every share
			for(int j=0; j < n; j++) {

                              if (checkForZeros(a)) {
                                System.err.println("all a coefficients are zero");
                                System.err.println("i: " + i + " data.length: " + data.length);
                                shares[j].yValues[fillPosition] = 0;
                              } else {
                                shares[j].yValues[fillPosition] = (byte)(poly.evaluateAt(shares[j].xValue) & 0xFF);
                              }
			}
			fillPosition++;
		}
		
		return shares;	
	}

	@Override
	public byte[] reconstruct(Share[] shares) {
		
		int xValues[] = new int[k];
		byte result[] = new byte[shares[0].contentLength];
		
		for(int i=0; i < k; i++) {
			xValues[i] = shares[i].xValue;
		}
		
		int w = 0;
		try {

			CustomMatrix decodeMatrix = PolyGF256.erasureDecodePrepare(xValues);
			
			for(int i=0; i < shares[0].yValues.length; i++) {
			
				int yValues[] = new int[k];
				for(int j=0; j < k; j++)	{
					yValues[j] = (shares[j].yValues[i] < 0) ? (shares[j].yValues[i] + 256) : shares[j].yValues[i];
				}

				if (checkForZeros(yValues)) {
                                  for(int x=0; x < k && w < result.length; x++) {
                                    result[w++] = 0;
                                  }
				} else {
                                  int resultMatrix[] = decodeMatrix.rightMultiply(yValues);
				
                                  for(int j=resultMatrix.length-1; j >= 0 && w < shares[0].contentLength; j--) {
                                          int element = resultMatrix[resultMatrix.length -1 -j];
                                          result[w++] = (byte)(element & 0xFF);
                                  }
                                }
			}
		} catch(ReconstructionException ex) {
			throw new ImpossibleException(ex);
		}
		return result;
	}
}
