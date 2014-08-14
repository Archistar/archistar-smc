package at.archistar.crypto;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import at.archistar.crypto.data.VSSShare;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.exceptions.ImpossibleException;
import at.archistar.crypto.exceptions.ReconstructionException;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.random.SHA1PRNG;
import at.archistar.helper.ShareHelper;
import at.archistar.helper.ShareMacHelper;

/**
 * <p>This class implements the <i>Rabin-Ben-Or Robust Secret-Sharing </i> scheme.</p>
 * 
 * <p>For a detailed description of the scheme, 
 * see: <a href="http://www.cse.huji.ac.il/course/2003/ns/Papers/RB89.pdf">http://www.cse.huji.ac.il/course/2003/ns/Papers/RB89.pdf</a></p>
 * 
 * 
 * @author Elias Frantar <i>(code refactored, documentation added)</i>
 * @author Andreas Happe <andreashappe@snikt.net>
 * @author Thomas Loruenser <thomas.loruenser@ait.ac.at>
 * @version 2014-7-24
 */
public class RabinBenOrRSS extends SecretSharing {
	private final String MAC = "HMacSHA256";
	private final int KEY_LENGTH = 16;
	private final int TAG_LENGTH = 32;
	
    private SecretSharing sharing;
    private ShareMacHelper mac;

    /**
     * Constructor
     * 
     * @param sharing the Secret-Sharing algorithm to use as a base for this scheme (must not be itself!)
     * @throws WeakSecurityException 
     */
    public RabinBenOrRSS(SecretSharing sharing) throws WeakSecurityException {
    	super(sharing.getN(), sharing.getK());
    	
    	if (sharing instanceof RabinBenOrRSS)
    		throw new IllegalArgumentException("the underlying scheme must not be itself");
    	if (sharing instanceof RabinIDS)
    		throw new ImpossibleException("Reed-Solomon-Code is not secure!");
        
        this.sharing = sharing;
        try { 
        	this.mac = new ShareMacHelper(MAC, new SHA1PRNG());
        } catch (NoSuchAlgorithmException e) { // this should never happen
        	throw new ImpossibleException(e);
        }
    }

    @Override
    public Share[] share(byte[] data) {
        VSSShare[] rboshares = ShareHelper.createVSSShares(sharing.share(data), TAG_LENGTH, KEY_LENGTH);
        
		/* compute and add the corresponding tags */
		for(VSSShare share1 : rboshares) {
			for(VSSShare share2 : rboshares) {
				try {
					byte[] key = mac.genSampleKey(KEY_LENGTH);
					byte[] tag = mac.computeMAC(share1.getShare(), key, TAG_LENGTH);
					
					share1.getMacs().put((byte) share2.getId(), tag);
					share2.getMacKeys().put((byte) share1.getId(), key);
				}
				catch(Exception e) { return null; }
			}
		}
		
        return rboshares;
    }

    @Override
    public byte[] reconstruct(Share[] shares) throws ReconstructionException {
    	VSSShare[] rboshares = safeCast(shares); // we need access to it's inner fields
		Share[] valid = new Share[rboshares.length];
		int counter = 0;
		
		for (int i = 0; i < rboshares.length; i++) { // go through all shares
			int accepts = 0; // number of participants accepting i
			for(VSSShare rboshare: rboshares) { // go through all shares
				try { 
					accepts += (mac.verifyMAC(rboshares[i].getShare(), rboshares[i].getMacs().get((byte) rboshare.getId()),
												            rboshare.getMacKeys().get((byte) rboshares[i].getId()))
							      ) ? 1 : 0; // verify the mac with the corresponding key for each share
				} catch(Exception e) { } // catch faulty shares
			}
			
			if(accepts >= k) { // if there are at least k accepts, this share is counted as valid
				valid[counter++] = rboshares[i].getShare();
			}
		}
		
		if(counter >= k) {
			return sharing.reconstruct(Arrays.copyOfRange(valid, 0, counter));
		}
		
		throw new ReconstructionException(); // if there weren't enough valid shares
    }
    
    /**
     * Converts the Share[] to a RabinBenOrShare[] by casting each element individually.
     * 
     * @param shares the shares to cast
     * @return the given Share[] as RabinBenOrShare[]
     * @throws ClassCastException if the Share[] did not (only) contain RabinBenOrShares
     */
    private VSSShare[] safeCast(Share[] shares) {
    	VSSShare[] rboshares = new VSSShare[shares.length];
    	
    	for (int i = 0; i < shares.length; i++) {
    		rboshares[i] = (VSSShare) shares[i];
    	}
    	
    	return rboshares;
    }
}
