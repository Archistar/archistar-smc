package at.archistar.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import at.archistar.crypto.data.KrawczykShare;
import at.archistar.crypto.data.KrawczykShare.EncryptionAlgorithm;
import at.archistar.crypto.data.ReedSolomonShare;
import at.archistar.crypto.data.ShamirShare;
import at.archistar.crypto.data.Share;
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

    private final EncryptionAlgorithm ALG = EncryptionAlgorithm.AES;

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
	        Cipher cipher = Cipher.getInstance(ALG.getAlgString());
	        cipher.init(Cipher.ENCRYPT_MODE, sKeySpec, new IvParameterSpec(encKey));
	        byte[] encSource = cipher.doFinal(data);
	
	        //Share the encrypted secret
	        ReedSolomonShare[] contentShares = (ReedSolomonShare[]) rs.share(encSource); // we need access to the inner fields
	
	        //Share the key
	        ShamirShare[] keyShares = (ShamirShare[]) shamir.share(encKey); // we nee access to the inner fields
	
	        //Generate a new array of encrypted shares
	        KrawczykShare[] shares = new KrawczykShare[contentShares.length];
	        for (int i = 0; i < shares.length; i++) {
	            assert contentShares[i].getId() == keyShares[i].getId();
	            shares[i] = new KrawczykShare((byte) contentShares[i].getId(), contentShares[i].getY(), encSource.length, keyShares[i].getY(), ALG);
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
    		KrawczykShare[] kshares = safeCast(shares); // we need access to the inner fields
    		
	        /* extract key */
	        ShamirShare keyShares[] = new ShamirShare[kshares.length];
	        for (int i = 0; i < kshares.length; i++) {
	            keyShares[i] = new ShamirShare((byte) kshares[i].getId(), kshares[i].getKeyY());
	        }
	        byte[] key = this.shamir.reconstruct(keyShares);
	
	        /* reconstruct share */
	        ReedSolomonShare contentShares[] = new ReedSolomonShare[kshares.length];
	        for (int i = 0; i < kshares.length; i++) {
	            contentShares[i] = new ReedSolomonShare((byte) kshares[i].getId(), kshares[i].getY(), kshares[i].getOriginalLength());
	        }
	        byte[] share = this.rs.reconstruct(contentShares);
	
	        /* use the key to decrypt the 'original' share */
	        SecretKeySpec sKeySpec = new SecretKeySpec(key, "AES");
	        Cipher cipher = Cipher.getInstance(kshares[0].getEncryptionAlgorithm().getAlgString());
	        cipher.init(Cipher.DECRYPT_MODE, sKeySpec, new IvParameterSpec(sKeySpec.getEncoded()));
	        return cipher.doFinal(share);
    	} catch (Exception e) { // if something went wrong
    		throw new ReconstructionException();
    	}
    }
    
    /**
     * Converts the Share[] to a KrawczykShare[] by casting each element individually.
     * 
     * @param shares the shares to cast
     * @return the given Share[] as KrawczykShare[]
     * @throws ClassCastException if the Share[] did not (only) contain KrawczykShares
     */
    private KrawczykShare[] safeCast(Share[] shares) {
    	KrawczykShare[] kshares = new KrawczykShare[shares.length];
    	
    	for (int i = 0; i < shares.length; i++) {
    		kshares[i] = (KrawczykShare) shares[i];
    	}
    	
    	return kshares;
    }
}
