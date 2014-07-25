package at.archistar.helper;

import java.util.HashMap;
import java.util.Map;

import at.archistar.crypto.data.RabinBenOrShare;
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
	        y[j] = shares[j].getY()[i];
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
