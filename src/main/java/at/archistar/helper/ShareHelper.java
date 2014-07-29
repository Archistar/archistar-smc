package at.archistar.helper;

import java.util.HashMap;
import java.util.Map;

import at.archistar.crypto.data.KrawczykShare;
import at.archistar.crypto.data.KrawczykShare.EncryptionAlgorithm;
import at.archistar.crypto.data.VSSShare;
import at.archistar.crypto.data.ReedSolomonShare;
import at.archistar.crypto.data.ShamirShare;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.exceptions.ImpossibleException;
import at.archistar.crypto.exceptions.WeakSecurityException;

/**
 * This class provides some methods to outsource the initial creation of the Share[]s and also some other small utilities from
 * the individual SecretSharing schemes.
 * 
 * @author Elias Frantar
 * @version 2014-7-28
 */
public class ShareHelper {
	private ShareHelper() {} // just to not make it show up in javadoc
	
	/**
	 * Extracts all x-values from the given Share[].
	 * @param shares the shares to extract the x-values from
	 * @return an array with all x-values from the given shares (in same order as the given Share[])
	 */
	public static int[] extractXVals(Share[] shares) {
	    int[] x = new int[shares.length];
	    
	    for (int i = 0; i < x.length; i++) {
	        x[i] = shares[i].getId();
	    }
	    
	    return x;
	}
	
	/**
	 * Extracts all i<sup>th</sup> y-values from the given Share[].
	 * 
	 * @param shares the shares to extract the y-values from
	 * @param i the index of the y-value to extract from each share
	 * @return an array with all i<sup>th</sup> y-values from the given shares (in same order as the given Share[])
	 */
	public static int[] extractYVals(ShamirShare[] shares, int i) {
	    int[] y = new int[shares.length];
	    
	    for (int j = 0; j < y.length; j++) {
	        y[j] = ByteUtils.toUnsignedByte(shares[j].getY()[i]);
	    }
	    
	    return y;
	}
	
	/**
	 * Creates <i>n</i> ShamirShares with the given share-length.
	 * 
	 * @param n the number of ShamirShares to create
	 * @param shareLength the length of all shares
	 * @return an array with the created shares
	 */
	public static ShamirShare[] createShamirShares(int n, int shareLength) {
	    ShamirShare[] sshares = new ShamirShare[n];
	    
	    for (int i = 0; i < n; i++) {
	        sshares[i] = new ShamirShare((byte) (i+1), new byte[shareLength]);
	    }
	    
	    return sshares;
	}
	
	/**
     * Creates <i>n</i> ReedSolomonShares with the given share- and original-length.
     * 
     * @param n the number of ReedSolomonShare to create
     * @param shareLength the length of all shares
     * @return an array with the created shares
     */
	public static ReedSolomonShare[] createReedSolomonShares(int n, int shareLength, int originalLength) {
	    ReedSolomonShare[] rsshares = new ReedSolomonShare[n];
        
        for (int i = 0; i < n; i++) {
            rsshares[i] = new ReedSolomonShare((byte) (i+1), new byte[shareLength], originalLength);
        }
        
        return rsshares;
	}
	
	/**
	 * Create <i>n</i> KrawczykShares from the given Shamir- and Reed-Solomon shares.
	 * @param sshares the ShamirShares (key-shares)
	 * @param rsshares the ReedSolomonShares (content-shares)
	 * @param algorithm the algorithm used for encryption
	 * @return an array with the created shares
	 */
	public static KrawczykShare[] createKrawczykShares(ShamirShare[] sshares, ReedSolomonShare[] rsshares, EncryptionAlgorithm algorithm) {
	    assert sshares.length == rsshares.length; // both Share[] must have the same length
	    
	    KrawczykShare[] kshares = new KrawczykShare[sshares.length];
	    for (int i = 0; i < kshares.length; i++) {
	        kshares[i] = new KrawczykShare((byte) rsshares[i].getId(), rsshares[i].getY(), rsshares[i].getOriginalLength(), sshares[i].getY(), algorithm);
	    }
	    
	    return kshares;
	}
	
	/**
	 * Extracts the key-shares from the given KrawczykShares.
	 * @param kshares the shares to extract the key-shares from
	 * @return an array of the extracted key-shares
	 */
	public static ShamirShare[] extractKeyShares(KrawczykShare[] kshares) {
	    ShamirShare[] sshares = new ShamirShare[kshares.length];
	    
	    for (int i = 0; i < kshares.length; i++) {
	        sshares[i] = new ShamirShare((byte) kshares[i].getId(), kshares[i].getKeyY());
	    }
	    
	    return sshares;
	}
	
	/**
     * Extracts the content-shares from the given KrawczykShares.
     * @param kshares the shares to extract the content-shares from
     * @return an array of the extracted content-shares
     */
	public static ReedSolomonShare[] extractContentShares(KrawczykShare[] kshares) {
	    ReedSolomonShare[] rsshares = new ReedSolomonShare[kshares.length];
	    
	    for (int i = 0; i < kshares.length; i++) {
	        rsshares[i] = new ReedSolomonShare((byte) kshares[i].getId(), kshares[i].getY(), kshares[i].getOriginalLength());
	    }
	    
	    return rsshares;
	}
	
	/**
	 * Creates VSSShares using the given shares as underlying ones.
	 * 
	 * @param shares the underlying shares
	 * @param tagLength the length of a single tag
	 * @param keyLength the length of a single MAC-key
	 * @return the created RabinBenOrShares
	 */
	public static VSSShare[] createVSSShares(Share[] shares, int tagLength, int keyLength) {
		VSSShare[] vssshares = new VSSShare[shares.length];
		
		for (int i = 0; i < shares.length; i++) {
			/* initialize macs-Map */
			Map<Byte, byte[]> tmpMacs = new HashMap<Byte, byte[]>();
			for (Share tmpShare : shares) {
				tmpMacs.put((byte) tmpShare.getId(), new byte[tagLength]);
			}
			/* initialize macKeys-Map */
			Map<Byte, byte[]> tmpMacKeys = new HashMap<Byte, byte[]>();
			for (Share tmpShare : shares) {
				tmpMacKeys.put((byte) tmpShare.getId(), new byte[tagLength]);
			}
			
			try {
				vssshares[i] = new VSSShare(shares[i], tmpMacs, tmpMacKeys);
			} catch (WeakSecurityException e) { // this should never happen
				throw new ImpossibleException(e);
			}
		}
		
		return vssshares;
	}
	
	/**
	 * Extracts all underlying shares from the given VSSShares
	 * @param shares the shares to extract from
	 * @return an array of the extracted underlying shares
	 */
	public static Share[] extractUnderlyingShares(VSSShare[] shares) {
	    Share[] ushares = new Share[shares.length];
	    
	    for (int i = 0; i < shares.length; i++) {
	        ushares[i] = shares[i].getShare();
	    }
	    
	    return ushares;
	}
}
