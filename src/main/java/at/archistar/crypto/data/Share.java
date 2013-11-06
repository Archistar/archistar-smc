package at.archistar.crypto.data;

import java.util.HashMap;

/**
 * Simple wrapper class for created data shares. This is the
 * equivalent of a C 'struct' -- everything is public and we
 * are not even pretending to be object-oriented.
 * 
 * @author Andreas Happe <andreashappe@snikt.net>
 */
public class Share {
	
	public HashMap<Integer, byte[]> keys = new HashMap<Integer, byte[]>();
	public HashMap<Integer, byte[]> macs = new HashMap<Integer, byte[]>();
	
	public boolean accepted = false;
	
	public int contentLength;
	
	public int verificationCounter = 0;
	
	public Share(int xValue, int length, Type type) {
		this.xValue = xValue;
		this.yValues = new byte[length];
		this.type = type;
		this.key = null;
	}
	
	public Share(int xValue, int length, int originalLength, Type type) {
		this.xValue = xValue;
		this.yValues = new byte[length];
		this.type = type;
		this.key = null;
		this.contentLength = originalLength;
	}
	
	public Share(int xValue, byte[] yValues, byte[] key, int length, Type type) {
		this.xValue = xValue;
		this.yValues = yValues;
		this.key = key;
		this.type = type;
		this.contentLength = length;
	}

	public enum Type {
		REED_SOLOMON,
		SHAMIR,
		KRAWCZYK
	};
	
	final public Type type;
	
	final public int xValue;
	
	final public byte[] yValues;
	
	final public byte[] key;

	public Share newKeyShare() {
		return new Share(xValue, key, null, 0, Type.SHAMIR);
	}
}
