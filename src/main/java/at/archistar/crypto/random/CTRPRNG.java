package at.archistar.crypto.random;

import helper.ByteUtils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

/**
 * This is a counter-mode-cipher RNG outputting the result of running a symmetric cipher in counter-mode.
 * 
 * @author Elias Frantar
 * @version 2014-7-15
 */
public class CTRPRNG implements RandomSource {
	private final String ALGORITHM = "AES";
	private final String PARAMS = "/ECB/NoPadding"; // we don't need padding since the PRNG has nothing to pad; we perform CTR by ourself
	
	private Cipher cipher;
	
	private byte[] state;
	
	private byte[] cache; 
	private int counter;
	
	/**
	 * Constructor
	 */
	public CTRPRNG() {
		try {
			cipher = Cipher.getInstance(ALGORITHM + PARAMS);
			
			KeyGenerator kgen = KeyGenerator.getInstance(ALGORITHM);
			cipher.init(Cipher.ENCRYPT_MODE, kgen.generateKey());
			
			state = kgen.generateKey().getEncoded(); // simply reuse the keygen to compute the IV
			
			counter = 0;
			
			fillCache();
		} 
		catch (Exception e) {} // should never happen
	}
	
	/**
	 * Updates the cache with the encryption of the next block.
	 */
	private void fillCache() {
		cache = cipher.update(state);
		counter = 0;
		
		incrementState();
	}
	
	/**
	 * Increments the counter-block by one.
	 */
	private void incrementState() {
		for (int i = state.length - 1;i >= 0;i--) // take wrap arounds into account
			if(++state[i] != 0)
				break;
	}

	@Override
	public int generateCoefficient() {
		byte b;
		do
			if(counter > cache.length - 1)
				fillCache();
		while ((b = cache[counter++]) == 0); // result must not be 0
		
		return ByteUtils.toUnsignedByte(b);
	}
}