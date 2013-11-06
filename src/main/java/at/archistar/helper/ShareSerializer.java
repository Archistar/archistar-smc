package at.archistar.helper;

import java.nio.ByteBuffer;

import at.archistar.crypto.data.Share;

/**
 * Convert Share objects into byte[] and back
 * 
 * @author Andreas Happe <andreashappe@snikt.net>
 */
public class ShareSerializer {
	
	static private int getLengthFor(Share s) {
		switch(s.type) {
		case SHAMIR:
			return s.yValues.length + 6;
		case REED_SOLOMON:
			return s.yValues.length + 6;
		case KRAWCZYK:
			assert(s.key.length == 16);
			return s.yValues.length + 6 + s.key.length;
		default:
			assert(false);
		}
		return -1;
	}
	
	static public byte[] serializeShare(Share s) {
		byte[] blob = new byte[getLengthFor(s)];
		ByteBuffer length = ByteBuffer.allocate(4);
		int bufferPos = 0;
		
		blob[bufferPos++] = (byte)(s.type.ordinal() & 0xff);
		blob[bufferPos++] = (byte)(s.xValue);
		
		switch(s.type) {
		case SHAMIR:
			length.putInt(s.yValues.length);
			for(int i=0; i < 4; i++, bufferPos++) {
				blob[bufferPos] = length.get(i);
			}
			break;
		case REED_SOLOMON:
			length.putInt(s.contentLength);		
			for(int i=0; i < 4; i++, bufferPos++) {
				blob[bufferPos] = length.get(i);
			}
			break;			
		case KRAWCZYK:
			length.putInt(s.contentLength);

			for(int i=0; i < 4; i++, bufferPos++) {
				blob[bufferPos] = length.get(i);
			}
			
			for(int j=0; j < s.key.length; j++, bufferPos++) {
				blob[bufferPos] = s.key[j];
			}
			break;
		default:
			assert(false);
		}
		
		for(int j=0; j < s.yValues.length; j++, bufferPos++) {
			blob[bufferPos] = s.yValues[j];
		}
		
		return blob;
	}
	
	private static Share.Type getType(byte type) {
		if ((byte)(Share.Type.SHAMIR.ordinal() & 0xFF) == type) {
			return Share.Type.SHAMIR;
		} else if ((byte)(Share.Type.REED_SOLOMON.ordinal() & 0xFF) == type) {
			return Share.Type.REED_SOLOMON;
		} else if ((byte)(Share.Type.KRAWCZYK.ordinal() & 0xFF) == type) {
			return Share.Type.KRAWCZYK;
		}
		assert(false);
		return null;
	}

	static public Share deserializeShare(byte[] blob) {
		Share share = null;
		int bufferPos = 0;
		
		Share.Type type = getType(blob[bufferPos++]);
		byte xValue = blob[bufferPos++];
		
		ByteBuffer tmp = ByteBuffer.allocate(4);
		for(int i=0; i < 4; i++, bufferPos++) {
			tmp.put(i, blob[bufferPos]);
		}
		int length = tmp.getInt();
		
		switch(type) {
		case SHAMIR:
			share = new Share(xValue, length, type);
			for(int i=0; i < length; i++, bufferPos++) {
				share.yValues[i] = blob[bufferPos];
			}
			break;
		case REED_SOLOMON:
			share = new Share(xValue, blob.length - 6, length, type);
			for(int i=0; i < blob.length - 6; i++, bufferPos++) {
				share.yValues[i] = blob[bufferPos];
			}
			break;
		case KRAWCZYK:
			int restLength = blob.length - 2 - 16 - 4;
			share = new Share(xValue, new byte[restLength], new byte[16], length, type);
			for(int i=0; i < 16; i++, bufferPos++) {
				share.key[i] = blob[bufferPos];
			}
			for(int i=0; i < restLength; i++, bufferPos++) {
				share.yValues[i] = blob[bufferPos];
			}
			break;
		default:
			assert(false);
		}
		return share;
	}
}