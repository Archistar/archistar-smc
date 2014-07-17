package at.archistar.crypto;

import helper.ShareHelper;
import helper.ShareMacHelper;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import at.archistar.crypto.data.Share;
import at.archistar.crypto.decode.PolySolver;
import at.archistar.crypto.exceptions.ImpossibleException;
import at.archistar.crypto.exceptions.ReconstructionException;
import at.archistar.crypto.random.SHA1PRNG;

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
 * @version 2014-7-15
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
     */
    public RabinBenOrRSS(SecretSharing sharing) {
    	if (sharing instanceof RabinBenOrRSS)
    		throw new IllegalArgumentException("the underlying scheme must not be itself");
    	if (sharing instanceof ReedSolomon)
    		throw new ImpossibleException("Reed-Solomon-Code is not secure!");
    	
    	this.k = sharing.getK();
        
        this.sharing = sharing;
        try { this.mac = new ShareMacHelper(MAC, new SHA1PRNG()); } catch (NoSuchAlgorithmException e) {} // this should never happen
    }

    @Override
    public Share[] share(byte[] data) {
        Share[] shares = sharing.share(data);
        ShareHelper.initForMacs(shares, TAG_LENGTH, KEY_LENGTH);
        
		/* compute and add the corresponding tags */
		for(Share share1 : shares) {
			for(Share share2 : shares) {
				try {
					byte[] key = mac.genSampleKey(KEY_LENGTH);
					byte[] tag = mac.computeMAC(share1, key, TAG_LENGTH);
					
					share1.setTag((byte) share2.getX(), tag);
					share2.setMacKey((byte) share1.getX(), key);
				}
				catch(Exception e) { return null; }
			}
		}
		
        return shares;
    }

    @Override
    public byte[] reconstruct(Share[] shares) throws ReconstructionException {
    	int[] accepts = new int[shares.length]; // counts the number of accepts for every share
		Share[] valid = new Share[shares.length];
		int counter = 0;
		
		for(int i = 0;i < shares.length;i++) { // go through all shares
			for(Share rboshare: shares) // go through all shares
				try { 
					accepts[i] += (mac.verifyMAC(shares[i], shares[i].getTag((byte) rboshare.getX()), rboshare.getMacKey((byte) shares[i].getX())))?1:0; // verify the mac with the corresponding key for each share
				} catch(Exception e) { } // catch faulty shares
			
			if(accepts[i] >= k) // if there are at least k accepts, this share is probably valid
				valid[counter++] = shares[i];
		}
		
		if(counter >= k)
			return sharing.reconstruct(Arrays.copyOfRange(valid, 0, counter));
		
		throw new ReconstructionException(); // if there weren't enough valid shares
    }
    
	/* Setters for optionally exchangeable fields */
    
    @Override
    public void setSolver(PolySolver solver) {
    	sharing.setSolver(solver); // set the solver to the underlying sharing scheme
    }
}