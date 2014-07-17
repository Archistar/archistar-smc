/*
 * Questions:
 * 1) How to calculate the security parameters (key and tag-length)
 * 2) How to do the Reed-Solomon-Error-Correction?
 * 3) Performance ??? (HMacSHA256 not optimal)
 * 
 * [4) Why sharing the whole files and not only a key for a symmetric cipher?]
 */
package at.archistar.crypto;

import helper.ShareHelper;
import helper.ShareMacHelper;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import at.archistar.crypto.data.Share;
import at.archistar.crypto.decode.BerlekampWelchDecoder;
import at.archistar.crypto.exceptions.ImpossibleException;
import at.archistar.crypto.exceptions.ReconstructionException;
import at.archistar.crypto.random.SHA1PRNG;

/**
 * <p>This class implements the <i>Unconditionally-Secure Robust Secret Sharing with Compact Shares</i>-scheme developed by:
 * Alfonso Cevallos, Serge Fehr, Rafail Ostrovsky, and Yuval Rabani.</p>
 * 
 * <p>This system basically equals the RabinBenOrRSS, but has shorter tags and therefore requires a different, 
 * more secure reconstruction phase.</p>
 * 
 * <p>For detailed information about this system, see: 
 * <a href="http://www.iacr.org/cryptodb/data/paper.php?pubkey=24281">http://www.iacr.org/cryptodb/data/paper.php?pubkey=24281</a></p>
 * 
 * @author Elias Frantar
 * @version 2014-7-15
 */
public class USRSSwCompactShares extends SecretSharing {
	private final String MAC = "HMacSHA512";
	private final int E = 128; // security constant for computing the tag length; means 128 bit
	
	private int keyTagLength;
	
	private final SecretSharing sharing;
	private ShareMacHelper mac; // final has been omitted to allow a try/catch-block in constructor
	
	/**
	 * Constructor
	 * 
	 * @param n the number of shares to create
	 * @param k the minimum number of (correct) shares required to reconstruct the message (degree of the polynomial + 1)
	 * 			must be in range: <i>n/3 <= k-1 < n/2</i> ({@link ImpossibleException} if thrown if that constraint is violated)
	 */
	public USRSSwCompactShares(int n, int k) {
		if(k-1 >= n/3 && k-1 < n/2)
			throw new ImpossibleException("this scheme only works when n/3 <= t < n/2 (where t = k-1)");
		
		this.k = k;
		this.n = n;
		
		/* this scheme requires ShamirPSS and Berlekamp-Welch decoder */
		sharing = new ShamirPSS(n, k);
		((ShamirPSS) sharing).setSolver(new BerlekampWelchDecoder(k-1));
		
		try { mac = new ShareMacHelper(MAC, new SHA1PRNG()); } // we are using HMacSHA256 at the moment
		catch(NoSuchAlgorithmException e) { } // this should never happen
	}
	
	@Override
	public Share[] share(byte[] data) {
		keyTagLength = computeTagLength(data.length * 8, k, E);
				
		Share[] shares = sharing.share(data);
        ShareHelper.initForMacs(shares, keyTagLength, keyTagLength);
		
		/* compute and add the corresponding tags */
		for(Share share1 : shares) {
			for(Share share2 : shares) {
				try {
					byte[] key = mac.genSampleKey(keyTagLength);
					byte[] tag = mac.computeMAC(share1, key, keyTagLength);
					
					share1.setTag((byte) share2.getX(), tag);
					share2.setMacKey((byte) share1.getX(), key);
				}
				catch(Exception e) { return null; }
			}
		}
		
		return shares;
	}

	@Override
	public byte[] reconstruct(Share[] shares) throws ReconstructionException{
		/* create an accepts table */
		boolean[][] accepts = new boolean[n + 1][n + 1];
		
		for (Share s1 : shares)
			for (Share s2 : shares)
				try { accepts[s1.getX()][s2.getX()] = mac.verifyMAC(s1, s1.getTag((byte) s2.getX()), s2.getMacKey((byte) s1.getX())); }
				catch (Exception e) {} // catch faulty shares
		
		/* build a group I such that only shares with at least k accepts are in there */
		List<Share> valid = new LinkedList<Share>(Arrays.asList(shares));
		
		boolean finished = false;
		while(!finished) {
			finished = true;
			
			Iterator<Share> i1 = valid.iterator();
			while(i1.hasNext()) {
				Share s1 = i1.next();
			
				/* count the number of accepts for the current share */
				int count = 0;
				for(Share s2 : valid)
					try { count += (accepts[s1.getX()][s2.getX()]) ? 1 : 0; }
					catch (Exception e) {} // ArrayIndexOutOfBoundsException may be thrown when x is not valid
				
				if(count < k) { // share is not accepted by enough others
					i1.remove();
					
					/* start over */
					finished = false;
					break;
				}
			}
		}
		
		if(valid.size() >= k) // not enough shares for reconstruction
			return sharing.reconstruct(valid.toArray(new Share[valid.size()]));
		
		throw new ReconstructionException(); // if there weren't enough valid shares
	}
	
	/* helper functions */
	
	/**
	 * Computes the required MAC-tag-length to achieve a security of <i>e</i> bits.
	 * 
	 * @param m the length of the message in bit
	 * @param k the number of shares required for reconstruction
	 * @param e the security constant in bit
	 * @return the amount of bytes the MAC-tags should have
	 */
	private int computeTagLength(int m, int k, int e) {
		return (log2(k) + log2(m) + 2/k*e + log2(e)) / 8; // result in bytes
	}
	
	/**
	 * Computes the integer logarithm base 2 of a given number.
	 * 
	 * @param n the int to compute the logarithm for
	 * @return the integer logarithm (whole number -> floor()) of the given number
	 */
	private int log2(int n){
	    if (n <= 0) 
	    	throw new IllegalArgumentException();
	    
	    return 31 - Integer.numberOfLeadingZeros(n);
	}
}