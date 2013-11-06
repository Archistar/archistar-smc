package at.archistar.crypto.data;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import at.archistar.crypto.random.RandomSource;

/**
 * simple (key-)inefficient hash generator
 * 
 * @author Andreas Happe <andreashappe@snikt.net>
 */
public class MacSha512 implements MacHelper {
	
	private final String algorithm = "HMacSHA512";
	
	private final RandomSource rng;
	
	public MacSha512(RandomSource rng) {
		this.rng = rng;
	}

	@Override
	public byte[] getKeyForHash() throws NoSuchAlgorithmException {
		Mac hmac = Mac.getInstance(algorithm);
		byte[] key = new byte[hmac.getMacLength()];
						
		for(int k=0; k < hmac.getMacLength(); k++) {
			key[k] = (byte)(rng.generateByte() & 0xFF);
		}
		return key;
	}

	@Override
	public byte[] getHash(byte[] key, int xValue, byte[] yValues, byte[] keys) throws NoSuchAlgorithmException, InvalidKeyException {
		Mac hmac = Mac.getInstance(algorithm);
		Key k = new SecretKeySpec(key, hmac.getAlgorithm());
		hmac.init(k);
		
		hmac.update((byte)(xValue & 0xFF));
		if (keys != null && keys.length != 0) {
			hmac.update(keys);
		}
			
		return hmac.doFinal(yValues);
	}
}
