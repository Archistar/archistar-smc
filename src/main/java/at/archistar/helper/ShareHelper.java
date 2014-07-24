package at.archistar.helper;

import java.util.HashMap;
import java.util.Map;

import at.archistar.crypto.data.RabinBenOrShare;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.exceptions.ImpossibleException;
import at.archistar.crypto.exceptions.WeakSecurityException;

public class ShareHelper {
	private ShareHelper() {} // just to not make it show up in javadoc
	
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
