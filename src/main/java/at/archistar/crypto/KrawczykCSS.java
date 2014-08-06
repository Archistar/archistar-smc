package at.archistar.crypto;

import at.archistar.helper.ShareHelper;
import at.archistar.helper.SymmetricEncHelper;
import at.archistar.crypto.data.KrawczykShare;
import at.archistar.crypto.data.KrawczykShare.EncryptionAlgorithm;
import at.archistar.crypto.data.ReedSolomonShare;
import at.archistar.crypto.data.ShamirShare;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.decode.ErasureDecoder;
import at.archistar.crypto.exceptions.ImpossibleException;
import at.archistar.crypto.exceptions.ReconstructionException;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.random.RandomSource;
import at.archistar.crypto.random.SHA1PRNG;

/**
 * <p>This class implements the <i>Computational Secret Sharing</i> scheme developed by Krawczyk.</p>
 *  
 * <p>In short, this system combines the insecure but very fast and most importantly space efficient {@link ReedSolomon} 
 * with symmetric encryption with the perfectly secure {@link ShamirPSS} for sharing the key.</p>
 * 
 * <p>For detailed information about this scheme, see: 
 * <a href="http://courses.csail.mit.edu/6.857/2009/handouts/short-krawczyk.pdf">http://courses.csail.mit.edu/6.857/2009/handouts/short-krawczyk.pdf</a></p>
 * 
 * <p><b>NOTE:</b> This implementation uses <i>AES-128 in CBC-mode with PKCS5Padding</i> for encrypting the secret.</p>
 * 
 * @author Elias Frantar <i>(code rewritten, documentation added)</i>
 * @author Andreas Happe <andreashappe@snikt.net>
 * @author Thomas Loruenser <thomas.loruenser@ait.ac.at>
 * @version 2014-7-28
 */
public class KrawczykCSS extends SecretSharing {
    private final EncryptionAlgorithm ALG = EncryptionAlgorithm.AES;
    private final int KEY_LENGTH = 128;
    
	private final SecretSharing shamir;
    private final SecretSharing rs;

    /**
     * Constructor
     * (Applying the default settings for the Shamir-RNG and the decoders: {@link SHA1PRNG} and {@link ErasureDecoder})
     * 
     * @param n the number of shares
     * @param k the minimum number of shares required for reconstruction
     * @param rng the RandomSource to be used for the underlying Shamir-scheme
     * @throws WeakSecurityException thrown if this scheme is not secure for the given parameters
     */
    public KrawczykCSS(int n, int k, RandomSource rng) throws WeakSecurityException {
        super(n, k);
        
        shamir = new ShamirPSS(n, k, rng); // use a SharmirSecretSharing share generator to share the key and the content
        rs = new RabinIDS(n, k); // use RabinIDS for sharing Content 
    }

    @Override
    public Share[] share(byte[] data) {
		try {
	    	/* encrypt the data */
			byte[] encKey = SymmetricEncHelper.genRandomSecretKey(ALG.getAlgString(), KEY_LENGTH);
			byte[] encSource = SymmetricEncHelper.encrypt(ALG.getAlgString(), encKey, data);

			/* share key and content */
			Share[] contentShares = rs.share(encSource); // since the content is encrypted the share does not have to be perfectly secure (-> Reed-Solomon-Code)
			Share[] keyShares = shamir.share(encKey);

			//Generate a new array of encrypted shares
			return ShareHelper.createKrawczykShares((ShamirShare[]) keyShares, (ReedSolomonShare[]) contentShares, ALG);
		} catch(Exception e) { 
		    throw new ImpossibleException("sharing failed (" + e.getMessage() + ")");
		} // encryption should actually never fail
    }

    @Override
    public byte[] reconstruct(Share[] shares) throws ReconstructionException {
    	try {   
    	    KrawczykShare[] kshares = safeCast(shares);
    	    
	        byte[] key = shamir.reconstruct(ShareHelper.extractKeyShares(kshares)); // reconstruct the key
	        byte[] encShare = rs.reconstruct(ShareHelper.extractContentShares(kshares)); // reconstruct the encrypted share

        	return SymmetricEncHelper.decrypt(ALG.getAlgString(), key, encShare); // decrypt the encrypted data with the extracted key
    	}
        catch(Exception e) {
        	throw new ReconstructionException();
        }
    }
    
    /**
     * Converts the Share[] to a KrawczykShare[] by casting each element individually.
     * 
     * @param shares the shares to cast
     * @return the given Share[] as KrawczykShare[]
     * @throws ClassCastException if the Share[] did not (only) contain KrawczykShare
     */
    private KrawczykShare[] safeCast(Share[] shares) {
        KrawczykShare[] kshares = new KrawczykShare[shares.length];
        
        for (int i = 0; i < shares.length; i++) {
            kshares[i] = (KrawczykShare) shares[i];
        }
        
        return kshares;
    }
}
