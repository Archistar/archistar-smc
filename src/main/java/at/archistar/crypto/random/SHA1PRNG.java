package at.archistar.crypto.random;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import at.archistar.helper.ByteUtils;

/**
 * A wrapper class for the internal java SHA1-PRNG (also used in Java's {@link SecureRandom}).
 * 
 * <p><b>NOTE:</b> Since this PRNG is secure it is used as default generator for all SecretSharing algorithms.</p>
 * 
 * @author Elias Frantar
 * @version 2014-7-18
 */
public class SHA1PRNG implements RandomSource {
	private final String ALGORITHM = "SHA1PRNG";
	
	private SecureRandom rng;
	
	/**
	 * Constructor<br>
	 * Immediately seeds the RNG with system-entropy. (may be a blocking call)
	 */
	public SHA1PRNG() { 
		try { 
			rng = SecureRandom.getInstance(ALGORITHM); 
		} catch (NoSuchAlgorithmException e) {} // this should never happen
		
		rng.nextBoolean(); // force the rng to seed itself
	}
	
	@Override
	public int generateByte() {
		/* this whole procedure is 2x as fast as nextInt(255) + 1 */
		byte[] bytes = new byte[1];
		
		do {
			rng.nextBytes(bytes);
		} while (bytes[0] == 0); // the random byte must not be 0
		
		return ByteUtils.toUnsignedByte(bytes[0]);
	}
}
