package helper;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import at.archistar.crypto.data.Share;
import at.archistar.crypto.random.RandomSource;

/**
 * A helper-class for computing and validating MACs for {@link Share}s.
 * 
 * @author Elias Frantar
 * @version 2014-7-14
 */
public class ShareMacHelper {
	private Mac mac;
	private RandomSource rng;
	
	/**
	 * Constructor
	 * 
	 * @param algorithm the MAC algorithm to use (for example <i>SHA-256</i>)
	 * @param rng the random number generator to use for generating keys
	 * @throws NoSuchAlgorithmException thrown if the given algorithm is not supported
	 */
	public ShareMacHelper(String algorithm, RandomSource rng) throws NoSuchAlgorithmException {
		mac = Mac.getInstance(algorithm);
		this.rng = rng;
	}
	
	/**
	 * @see #computeMAC(Share, byte[], int)
	 * Uses algorithms default MAC-length.
	 */
	public byte[] computeMAC(Share share, byte[] key) throws InvalidKeyException {
		return computeMAC(share, key, mac.getMacLength());
	}
	/**
	 * Computes the MAC of the specified length for the given share with the given key.
	 * 
	 * @param share the share to create the MAC for
	 * @param key the key to use for computing the MAC
	 * @param length the length of the returned tag
	 * @return the message authentication code (tag or MAC) for this share
	 * @throws InvalidKeyException thrown if an InvalidKeyException occurred
	 */
	public byte[] computeMAC(Share share, byte[] key, int length) throws InvalidKeyException {
	    Key k = new SecretKeySpec(key, mac.getAlgorithm());
	    mac.init(k);

	    /* add params to Mac */
	    mac.update((byte)share.getX());
	    mac.update(share.getY());

	    return Arrays.copyOfRange(mac.doFinal(), 0, length); // calculate tag
	}
	
	/**
	 * Verifies the given MAC.<br>
	 * (recomputes the tag from share and key and compares it with the given tag)
	 * 
	 * @param share the share to verify the MAC for
	 * @param tag the tag to verify
	 * @param key the key to use for verification
	 * @return true if verification was successful (the tags matched); false otherwise
	 */
	public boolean verifyMAC(Share share, byte[] tag, byte[] key) {
		boolean valid = false;
		
    	try {
			byte[] newTag = computeMAC(share, key, tag.length); // compute tag for the given parameters
			valid = Arrays.equals(tag, newTag); // compare with original tag
		} catch (InvalidKeyException e) {}
    	
    	return valid;
	}
	
	/**
	 * Generates a random MAC-key of specified length
	 * @param length the length of the key
	 * @return a newly-generated random MAC-key
	 */
	public byte[] genSampleKey(int length) {
		byte[] key = new byte[length];
		
		for(int i = 0;i < length;i++)
			key[i] = (byte)(rng.generateCoefficient() & 0xFF);
		
		return key;
	}
}