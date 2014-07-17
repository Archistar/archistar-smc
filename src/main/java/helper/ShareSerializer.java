package helper;

import java.nio.ByteBuffer;
import java.util.Arrays;

import at.archistar.crypto.data.Share;

/**
 * Provides utility to serialize and deserialize {@link Share}-objects into byte[] and back.
 *
 * @author Elias Frantar <i>(code rewritten, documentaiton added, features extended)</i>
 * @author Andreas Happe <andreashappe@snikt.net>
 * @version 2014-7-16
 */
public class ShareSerializer {
	
	/*
	 * Layout of a serialized share:
	 * 
	 * 1    1 4    n1                      4    n2        4    n3        n3        4
	 * |type|x|n1  |y......................|n2  |key......|n3  |tags.....|keys.....|o.l.|
	 *         					           {Krawczyk     }{Rabin-Ben-Or, USRSS    }{R.S.}
	 * 
	 */

	/**
	 * Computes the length of the byte[] required for serializing the given share.
	 * @param s the share to compute the serialized length for
	 * @return the length of the serialized share's byte[]
	 */
	private static int getLengthFor(Share s) {
		int length = s.getY().length + 6; // 1 (type), 1 (x), 4 (length of y)
		
		byte type = s.getType();
		if ((type & Share.REED_SOLOMON) != 0)
			length += 4; // 4 (original length)
		if ((type & Share.KRAWCZYK) != 0)
			length += 4 + s.getKeyY().length; // 4 (length of the key)
		if ((type & Share.RABIN_BEN_OR | type & Share.USRSS) != 0)
			length += (s.getMacKeys().length - 1) * s.getMacKeys()[0].length * 2 + 4; // 4 (length of keys and tags)
		
        return length;
    }

	/**
	 * Serializes the given share.
	 * @param s the share to serialize
	 * @return the serialized share (as a byte[])
	 */
    public static byte[] serializeShare(Share s) {
        byte[] blob = new byte[getLengthFor(s)];
        int bufferPos = 0;

        /* add fields required for all share types */
        blob[bufferPos++] = s.getType();
        blob[bufferPos++] = (byte) s.getX();
        
        for (byte b : toBytes(s.getY().length)) // add y-length and y-values
        	blob[bufferPos++] = b;
        for (byte b : s.getY())
        	blob[bufferPos++] = b;

        /* add fields for the individual share-types */
        byte type = s.getType();
        if ((type & Share.KRAWCZYK) != 0) {
        	for (byte b : toBytes(s.getKeyY().length))
        		blob[bufferPos++] = b;
        	for (byte b : s.getKeyY())
        		blob[bufferPos++] = b;
        }
        
		if ((type & Share.RABIN_BEN_OR | type & Share.USRSS) != 0) {
			for (byte b : toBytes(s.getMacKeys().length - 1))
        		blob[bufferPos++] = b;
			
			for (byte[] bb : Arrays.copyOfRange(s.getTags(), 1, s.getTags().length))
				for (byte b : bb)
					blob[bufferPos++] = b;
			for (byte[] bb : Arrays.copyOfRange(s.getMacKeys(), 1, s.getMacKeys().length))
				for (byte b : bb)
					blob[bufferPos++] = b;
		}
		
		if ((type &= Share.REED_SOLOMON) != 0)
			for (byte b : toBytes(s.getOriginalLength()))
        		blob[bufferPos++] = b;
    
        return blob;
    }

    /**
     * Deserializes the given serialized share.
     * @param blob the serialized share
     * @return the deserialized share as a {@link Share}-object
     */
    public static Share deserializeShare(byte[] blob) {
        int bufferPos = 0;

        byte type = blob[bufferPos++];
        byte xValue = blob[bufferPos++];
        
        /* create share and set requried fields */
        Share share = new Share(type);
        share.setX(xValue);

        byte[] y = new byte[ByteBuffer.wrap(Arrays.copyOfRange(blob, bufferPos, (bufferPos += 4))).getInt()];
        for (int i = 0; i < y.length; i++)
        	y[i] = blob[bufferPos++];
        share.setY(y);
        
        /* set fields for the individual share-types */
        if ((type & Share.KRAWCZYK) != 0) {
        	byte[] keyY = new byte[ByteBuffer.wrap(Arrays.copyOfRange(blob, bufferPos, (bufferPos += 4))).getInt()];
        	for (int i = 0; i < keyY.length; i++)
            	keyY[i] = blob[bufferPos++];
            share.setKeyY(keyY);
        }
        
		if ((type & Share.RABIN_BEN_OR | type & Share.USRSS) != 0) {
			int length = ByteBuffer.wrap(Arrays.copyOfRange(blob, bufferPos, (bufferPos += 4))).getInt();
			int individual_length = (blob.length - bufferPos - (((type &= Share.REED_SOLOMON) == 0) ? 0 : 4)) / (2 * length);
			
			share.initForMac(length, individual_length, individual_length);
			
			for (int i = 1; i <= length; i++) {
				byte[] tag = new byte[individual_length];
	        	for (int j = 0; j < tag.length; j++)
	            	tag[j] = blob[bufferPos++];
	            share.setTag((byte) (i), tag);
			}
			
			for (int i = 1; i <= length; i++) {
				byte[] key = new byte[individual_length];
	        	for (int j = 0; j < key.length; j++)
	            	key[j] = blob[bufferPos++];
	            share.setMacKey((byte) i, key);
			}
		}
		
		if ((type &= Share.REED_SOLOMON) != 0)
			share.setOriginalLength(ByteBuffer.wrap(Arrays.copyOfRange(blob, bufferPos, (bufferPos += 4))).getInt());
    
        return share;
    }
    
    /**
     * Converts an integer to its corresponding individual byte values.
     * @param i the int to convert into a byte[]
     * @return the bytes of the given integer
     */
    private static byte[] toBytes(int i) { // not using ByteBuffer to safe object and instantiation overhead
    	/*
    	 * @author http://stackoverflow.com/questions/1936857/convert-integer-into-byte-array-java?rq=1
    	 */
    	byte[] result = new byte[4];

    	result[0] = (byte) (i >> 24);
    	result[1] = (byte) (i >> 16);
    	result[2] = (byte) (i >> 8);
    	result[3] = (byte) (i /*>> 0*/);

    	return result;
    }
}