package at.archistar.helper;

import at.archistar.crypto.data.Share;

/**
 * Convert Share objects into byte[] and back
 * 
 * @author Andreas Happe <andreashappe@snikt.net>
 */
public class ShareSerializer {
	static public byte[] serializeShare(Share s) {
		byte[] blob = null;
		
		if (s.type == Share.Type.SHAMIR) {
			blob = new byte[1 + 1 + s.yValues.length];
			blob[0] = (byte)(s.type.ordinal() & 0xff);
			blob[1] = (byte)(s.xValue);
			for(int i=0; i < s.yValues.length; i++) {
				blob[i+2] = s.yValues[i];
			}
		}
		
		return blob;
	}

	static public Share deserializeShare(byte[] blob) {
		Share share = null;
		
		if (blob[0] == ((byte)(Share.Type.SHAMIR .ordinal() & 0xFF))) {
			share = new Share(blob[1], blob.length - 2, Share.Type.SHAMIR);
			for(int i=0; i < share.yValues.length; i++) {
				share.yValues[i] = blob[i+2];
			}
		}
		
		return share;
	}
}