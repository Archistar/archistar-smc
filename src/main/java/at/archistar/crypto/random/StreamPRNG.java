package at.archistar.crypto.random;

import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import at.archistar.crypto.exceptions.CryptoException;
import at.archistar.helper.ByteUtils;

/**
 * This is a stream-cipher RNG outputting the key-stream of a stream-cipher as random numbers.<br>
 * 
 * <p><b>NOTE:</b> This is the fastest secure PRNG in this package.</p>
 * 
 * @author Elias Frantar
 * @version 2014-7-18
 */
public class StreamPRNG implements RandomSource {
	
	/* supported algorithms */
	/**
	 * identifier for the <i>Salsa20</i> algorithm
	 */
	public static final String SALSA20 = "Salsa20";
	/**
	 * identifier for the <i>HC128</i> algorithm
	 * 
	 * <p><b>NOTE:</b> This is the fastest available algorithm in this package</p>
	 */
	public static final String HC128 = "HC128";
	
	
	private static byte[] dummy = new byte[16]; // we are only interested in the key-stream (so fill with 0s)
	static {
		Security.addProvider(new BouncyCastleProvider()); // we need to add the "bouncycastle"-provider only once
	}
	
	private Cipher cipher;
	
	private byte[] cache; 
	private int counter;
	
	/**
	 * Constructor
	 * @param algorithm the stream-cipher algorithm to use (do only pass constants of this class)
	 * @throws CryptoException thrown if initialization of the RNG failed
	 */
	public StreamPRNG(String algorithm) throws CryptoException {
		try {
			cipher = Cipher.getInstance(algorithm, "BC"); // we want implementations from bouncycastle
				
			KeyGenerator kgen = KeyGenerator.getInstance(algorithm, "BC");
			cipher.init(Cipher.ENCRYPT_MODE, kgen.generateKey());
				
			counter = 0;
				
			fillCache();
		} catch (Exception e) {
			throw new CryptoException("initializing the RNG faild (" + e.getMessage() + ")");
		}
	}
	
	/**
	 * Updates the cache with the next iteration of output from the stream-cipher.
	 */
	private void fillCache() {
		cache = cipher.update(dummy); // fill the cache with the keystream
		counter = 0;
	}

	@Override
	public int generateByte() {
		byte b;
		do {
			if(counter > cache.length - 1) {
				fillCache();
			}
		} while ((b = cache[counter++]) == 0); // result must not be 0
		
		return ByteUtils.toUnsignedByte(b);
	}
	
	@Override
	public String toString() { // just required for testing
		return super.toString() + " (" + cipher.getAlgorithm() + ")";
	}
}
