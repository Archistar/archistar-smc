package at.archistar.helper;

import java.util.HashMap;
import java.util.Map;

import at.archistar.crypto.data.KrawczykShare;
import at.archistar.crypto.data.KrawczykShare.EncryptionAlgorithm;
import at.archistar.crypto.data.RabinBenOrShare;
import at.archistar.crypto.data.ReedSolomonShare;
import at.archistar.crypto.data.ShamirShare;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.exceptions.ImpossibleException;
import at.archistar.crypto.exceptions.WeakSecurityException;

public class ShareHelper {
	private ShareHelper() {} // just to not make it show up in javadoc
	
	public static int[] extractXVals(Share[] shares) {
	    int[] x = new int[shares.length];
	    
	    for (int i = 0; i < x.length; i++) {
	        x[i] = shares[i].getId();
	    }
	    
	    return x;
	}
	
	public static int[] extractYVals(ShamirShare[] shares, int i) {
	    int[] y = new int[shares.length];
	    
	    for (int j = 0; j < y.length; j++) {
	        y[j] = ByteUtils.toUnsignedByte(shares[j].getY()[i]);
	    }
	    
	    return y;
	}
	
	public static ShamirShare[] createShamirShares(int n, int shareLength) {
	    ShamirShare[] sshares = new ShamirShare[n];
	    
	    for (int i = 0; i < n; i++) {
	        sshares[i] = new ShamirShare((byte) (i+1), new byte[shareLength]);
	    }
	    
	    return sshares;
	}
	
	public static ReedSolomonShare[] createReedSolomonShares(int n, int shareLength, int originalLength) {
	    ReedSolomonShare[] rsshares = new ReedSolomonShare[n];
        
        for (int i = 0; i < n; i++) {
            rsshares[i] = new ReedSolomonShare((byte) (i+1), new byte[shareLength], originalLength);
        }
        
        return rsshares;
	}
	
	public static KrawczykShare[] createKrawczykShares(ShamirShare[] sshares, ReedSolomonShare[] rsshares, EncryptionAlgorithm algorithm) {
	    assert sshares.length == rsshares.length;
	    
	    KrawczykShare[] kshares = new KrawczykShare[sshares.length];
	    for (int i = 0; i < kshares.length; i++) {
	        kshares[i] = new KrawczykShare((byte) rsshares[i].getId(), rsshares[i].getY(), rsshares[i].getOriginalLength(), sshares[i].getY(), algorithm);
	    }
	    
	    return kshares;
	}
	
	public static ShamirShare[] extractKeyShares(KrawczykShare[] kshares) {
	    ShamirShare[] sshares = new ShamirShare[kshares.length];
	    
	    for (int i = 0; i < kshares.length; i++) {
	        sshares[i] = new ShamirShare((byte) kshares[i].getId(), kshares[i].getKeyY());
	    }
	    
	    return sshares;
	}
	
	public static ReedSolomonShare[] extractContentShares(KrawczykShare[] kshares) {
	    ReedSolomonShare[] rsshares = new ReedSolomonShare[kshares.length];
	    
	    for (int i = 0; i < kshares.length; i++) {
	        rsshares[i] = new ReedSolomonShare((byte) kshares[i].getId(), kshares[i].getY(), kshares[i].getOriginalLength());
	    }
	    
	    return rsshares;
	}
	
	public static RabinBenOrShare[] createRabinBenOrShares(Share[] shares, int tagLength, int keyLength) {
		RabinBenOrShare[] rboshares = new RabinBenOrShare[shares.length];
		
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
				rboshares[i] = new RabinBenOrShare(shares[i], tmpMacs, tmpMacKeys);
			} catch (WeakSecurityException e) { // this should never happen
				throw new ImpossibleException(e);
			}
		}
		
		return rboshares;
	}
	
}
