package at.archistar.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import at.archistar.crypto.data.Share;
import at.archistar.crypto.data.Share.Type;
import at.archistar.crypto.exceptions.ImpossibleException;
import at.archistar.crypto.exceptions.ReconstructionException;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.random.RandomSource;

/**
 * @author Andreas Happe <andreashappe@snikt.net>
 * @author Thomas Loruenser <thomas.loruenser@ait.ac.at>
 */
public class KrawczykCSS extends SecretSharing {

    private final SecretSharing shamir;

    private final SecretSharing rs;

    private final String cipherOptions = "AES/CBC/PKCS5Padding";

    public KrawczykCSS(int n, int k, RandomSource rng) throws WeakSecurityException {
    	super(n, k);
    	
    	//Use a SharmirSecretSharing share generator to share the key and the content
        shamir = new ShamirPSS(n, k, rng);

        //Use RabinIDS for sharing Content
        rs = new RabinIDS(n, k);
    }

    @Override
    public Share[] share(byte[] data) {
    	try {
	        /* try to encrypt original data */
	        KeyGenerator kgen = KeyGenerator.getInstance("AES");
	        kgen.init(128);
	        SecretKey skey = kgen.generateKey();
	        byte[] encKey = skey.getEncoded();
	
	        SecretKeySpec sKeySpec = new SecretKeySpec(encKey, "AES");
	        Cipher cipher = Cipher.getInstance(cipherOptions);
	        cipher.init(Cipher.ENCRYPT_MODE, sKeySpec, new IvParameterSpec(encKey));
	        byte[] encSource = cipher.doFinal(data);
	
	        //Share the encrypted secret
	        Share[] contentShares = rs.share(encSource);
	
	        //Share the key
	        Share[] keyShares = shamir.share(encKey);
	
	        //Generate a new array of encrypted shares
	        Share[] shares = new Share[contentShares.length];
	        for (int i = 0; i < shares.length; i++) {
	            assert contentShares[i].xValue == keyShares[i].xValue;
	            shares[i] = new Share(contentShares[i].xValue, contentShares[i].yValues, keyShares[i].yValues, encSource.length, Type.KRAWCZYK);
	        }
	
	        return shares;
    	} catch (Exception e) { // encryption should actually never fail
    		throw new ImpossibleException(e);
    	}
    }

    @Override
    public byte[] reconstruct(Share[] shares) throws ReconstructionException {
    	if (shares.length < k) {
    		throw new ReconstructionException();
    	}
    	
    	try {
	        /* extract key */
	        Share keyShares[] = new Share[shares.length];
	        for (int i = 0; i < shares.length; i++) {
	            keyShares[i] = shares[i].newKeyShare();
	        }
	
	        byte[] key = this.shamir.reconstruct(keyShares);
	
	        /* reconstruct share */
	        byte[] share = this.rs.reconstruct(shares);
	
	        /* use the key to decrypt the 'original' share */
	        SecretKeySpec sKeySpec = new SecretKeySpec(key, "AES");
	        Cipher cipher = Cipher.getInstance(cipherOptions);
	        cipher.init(Cipher.DECRYPT_MODE, sKeySpec, new IvParameterSpec(sKeySpec.getEncoded()));
	        return cipher.doFinal(share);
    	} catch (Exception e) { // if something went wrong
    		throw new ReconstructionException();
    	}
    }
}
