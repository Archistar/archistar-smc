package at.archistar.crypto;

import helper.SymmetricEncHelper;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.decode.ErasureDecoder;
import at.archistar.crypto.decode.PolySolver;
import at.archistar.crypto.exceptions.ImpossibleException;
import at.archistar.crypto.exceptions.ReconstructionException;
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
 * @version 2014-7-15
 */
public class KrawczykCSS extends SecretSharing {
    private final String CIPHER = "AES/CBC/PKCS5Padding";
    private final int KEY_LENGTH = 128;
    
	private final SecretSharing shamir;
    private final SecretSharing rs;

    /**
     * Constructor
     * (Applying the default settings for the Shamir-RNG and the decoders: {@link SHA1PRNG} and {@link ErasureDecoder})
     * 
     * @param n the number of shares
     * @param k the minimum number of shares required for reconstruction
     */
    public KrawczykCSS(int n, int k) {
        shamir = new ShamirPSS(n, k); // use a SharmirSecretSharing share generator to share the key and the content
        rs = new ReedSolomon(n, k); // use RabinIDS for sharing Content 
    }

    @Override
    public Share[] share(byte[] data) {
		try {
	    	/* encrypt the data */
			byte[] encKey = SymmetricEncHelper.genRandomSecretKey(CIPHER, KEY_LENGTH);
			byte[] encSource = SymmetricEncHelper.encrypt(CIPHER, encKey, data);

			/* share key and content */
			Share[] contentShares = rs.share(encSource); // since the content is encrypted the share does not have to be perfectly secure (-> Reed-Solomon-Code)
			Share[] keyShares = shamir.share(encKey);

			//Generate a new array of encrypted shares
			Share[] shares = new Share[contentShares.length];
			for (int i = 0; i < shares.length; i++) {
				shares[i] = new Share((byte) (Share.KRAWCZYK | Share.REED_SOLOMON));
				shares[i].setX((byte) contentShares[i].getX());
				shares[i].setY(contentShares[i].getY());
				shares[i].setOriginalLength(contentShares[i].getOriginalLength());
				shares[i].setKeyY(keyShares[i].getY());
			}
			return shares;
		}
		catch(Exception e) { throw new ImpossibleException("sharing failed (" + e.getMessage() + ")"); } // encryption should actually never fail
    }

    @Override
    public byte[] reconstruct(Share[] shares) throws ReconstructionException {
    	try {
	    	/* extract the key */
	        Share keyShares[] = new Share[shares.length];
	        for (int i = 0; i < shares.length; i++) {
	            keyShares[i] = new Share(Share.SHAMIR);
	            keyShares[i].setX((byte) shares[i].getX());
	            keyShares[i].setY(shares[i].getKeyY());
	        }
	        
	        byte[] key = shamir.reconstruct(keyShares); // reconstruct the key
	        byte[] encShare = rs.reconstruct(shares); // reconstruct the encrypted share

        	return SymmetricEncHelper.decrypt(CIPHER, key, encShare); // decrypt the encrypted data with the extracted key
    	}
        catch(Exception e) {
        	throw new ReconstructionException();
        }
    }
    
    /* Setters for optionally exchangeable fields */
    
    @Override
    public void setSolver(PolySolver solver) {
    	/* we need to update the solver of both internally used SecretSharing schemes */
    	shamir.setSolver(solver);
    	rs.setSolver(solver);
    }
}