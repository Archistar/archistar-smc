package at.archistar.crypto;

import helper.ShareHelper;
import helper.ByteUtils;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.decode.ErasureDecoder;
import at.archistar.crypto.exceptions.ReconstructionException;
import at.archistar.crypto.math.GF256Polynomial;
import at.archistar.crypto.random.RandomSource;
import at.archistar.crypto.random.SHA1PRNG;

/**
 * <p>This class implements the <i>Perfect-Secret-Sharing</i>-scheme (PSS) developed by Adi Shamir.</p>
 * 
 * <p>For a detailed description of the scheme, 
 * see: <a href='http://en.wikipedia.org/wiki/Shamir's_Secret_Sharing'>http://en.wikipedia.org/wiki/Shamir's_Secret_Sharing</a></p>
 * 
 * @author Elias Frantar <i>(code rewritten, documentation added)</i>
 * @author Andreas Happe <andreashappe@snikt.net>
 * @author Fehrenbach Franca-Sofia
 * @author Thomas Loruenser <thomas.loruenser@ait.ac.at>
 * 
 * @version 2014-7-15
 */
public class ShamirPSS extends SecretSharing {
	private RandomSource rng;
	
    /**
     * Constructor<br>
     * (Applying the default settings for the RNG and the decoder: {@link SHA1PRNG} and {@link ErasureDecoder})
     * 
     * @param n the number of shares
     * @param k the minimum number of shares required for reconstruction
     */
	public ShamirPSS(int n, int k) {
		this.n = n;
		this.k = k;
		
		/* init default settings */
		rng = new SHA1PRNG();
		solver = new ErasureDecoder();
	}
	
	@Override
	public Share[] share(byte[] data) {
		Share[] shares = Share.createShamirShares(n, data.length); // prepare the shares
		
		/* calculate the x and y values for the shares */
		for (int i = 0; i < data.length; i++) {
			GF256Polynomial poly = createShamirPolynomial(ByteUtils.toUnsignedByte(data[i]), k-1); // generate a new random polynomial
			
			for (Share share : shares) // evaluate the x-values at the polynomial
				share.setY(i, (byte) poly.evaluateAt(share.getX()));
		}
		
		return shares;
	}

	@Override
	public byte[] reconstruct(Share[] shares) throws ReconstructionException {
		if (shares.length < k)
			throw new ReconstructionException();
		
		try {			
			byte[] result = new byte[shares[0].getY().length];
			int[] xVals = ShareHelper.extractXVals(shares);
			
	        solver.prepare(xVals);
	        
			for (int i = 0; i < result.length; i++) { // reconstruct all individual parts of the secret
				int[] yVals = ShareHelper.extractYVals(shares, i);
				
				result[i] = (byte) solver.solve(yVals)[0];
			}	
			
			return result;
		}
		catch(Exception e) {
			throw new ReconstructionException();
		}
	}
	
	/**
	 * Creates a new polynomial for Shamir-Secret-Sharing.<br>
	 * In other words a polynomials with <i>degree</i> random coefficients and secret as the constant coefficient.
	 * 
	 * @param secret the secret to share (the constant coefficient)
	 * @param degree the degree of the polynomial (number of random coefficients, must be <i>k</i>)
	 * @return a random polynomial with the specified parameters ready for sharing the secret
	 */
	private GF256Polynomial createShamirPolynomial(int secret, int degree) {
		int[] coeffs = new int[degree + 1];
		
		coeffs[0] = secret;
		
		for (int i = 1; i <= degree; i++)
			coeffs[i] = rng.generateCoefficient();
		
		return new GF256Polynomial(coeffs);
	}
	
	/* Setters for optionally exchangeable fields */
	
	/**
	 * <p>Sets the Random-Number-Generator, which will be used for generating the random coefficients.</p>
	 * 
	 * <p><b>NOTE:</b> the default one is: {@link SHA1PRNG}</p>
	 * @param rng the RNG to use
	 */
	public void setRandomSource(RandomSource rng) { this.rng = rng; }
}