package at.archistar.crypto.data;

import java.util.Arrays;

import helper.ByteUtils;

/**
 * This class stores all information of a share from a Secrete-Sharing-scheme.
 * 
 * @author Elias Frantar
 * @version 2014-7-16
 */
public class Share {
	
	/* constants identifying the different share-types */
	public static final byte SHAMIR = 1; // every constant should only have a single bit on
	public static final byte REED_SOLOMON = 2;
	public static final byte KRAWCZYK = 4;
	public static final byte USRSS = 8;
	public static final byte RABIN_BEN_OR = 16;
	
	private byte type; // the bitmask of the share-types
	
	/* the secret */
	protected byte x;
	protected byte[] y;
	
	private int originalLength; // original length for Reed-Solomon reconstruction
	
	private byte[] keyY; // key for Krawczy sharing
	
	/* keys and tags required for RabinBenOr and USRSS */
	private byte[][] tags;
	private byte[][] keys;
	
	/**
	 * Constructor
	 * 
	 * @param type the type of the constructed share (Do only pass constants of this class!)
	 */
	public Share(byte type) {
		this.type = type;
	}
			
	/**
	 * Validates the share on having allowed values in all necessary fields for its type.
	 * 
	 * @return true if the share is valid; false otherwise
	 */
	public boolean validate() {
		boolean valid = true;
		
		/* every valid share must contain a secret */
		valid &= x != 0; // x must not be 0
		valid &= y != null;

		if ((type & REED_SOLOMON) != 0)
			valid &= originalLength != 0;
		if ((type & KRAWCZYK) != 0)
			valid &= keyY != null;
		if ((type & RABIN_BEN_OR | type & USRSS) != 0) {
			valid &= tags != null;
			valid &= keys != null;
			valid &= tags.length == keys.length;
		}
			
		return valid;
	}
	
	/**
	 * Creates n new shares for the Shamir-scheme.
	 * 
	 * @param n the number of shares to return
	 * @param dataLength the length of the data that will be stored in that share (number of y-bytes)
	 * @return an array containing the shares
	 */
	public static Share[] createShamirShares(int n, int dataLength) {
		Share[] shares = new Share[n];
		
		for(int i = 0;i < n;i++) {
			shares[i] = new Share(SHAMIR);
			shares[i].setX((byte)(i + 1));
			shares[i].setY(new byte[dataLength]);
		}
		
		return shares;
	}
	
	/**
	 * Creates n new shares for the Reed-Solomon-scheme.
	 * 
	 * @param n the number of shares to return
	 * @param dataLength the length of the data that will be stored in that share (number of y-bytes)
	 * @param originalLength the length of the complete data that will be shared
	 * @return an array containing the shares
	 */
	public static Share[] createReedSolomonShares(int n, int dataLength, int originalLength) {
		Share[] shares = new Share[n];
		
		for(int i = 0;i < n;i++) {
			shares[i] = new Share(REED_SOLOMON);
			shares[i].setX((byte)(i + 1));
			shares[i].setY(new byte[dataLength]);
			shares[i].setOriginalLength(originalLength);
		}
		
		return shares;
	}
	
	/**
	 * Activates the MAC and key storage in this share.
	 * 
	 * @param n the number of MACs to store
	 * @param tagLength the length of an individual MAC-tag
	 * @param keyLength the length of an individual MAC-key
	 */
	public void initForMac(int n, int tagLength, int keyLength) {
		tags = new byte[n + 1][tagLength]; // first index will be 1 (since x-values cannot be 0)
		keys = new byte[n + 1][keyLength];
	}
	
	/* Getters and Setters */
	public void setType(byte type) { this.type = type; }
	public void updateType(byte type) { this.type |= type; }
	public void setX(byte x) { this.x = x; }
	public void setY(byte[] y) { this.y = y; }
	public void setY(int i, byte b) { y[i] = b; }
	public void setOriginalLength(int originalLenght) { this.originalLength = originalLenght; }
	public void setKeyY(byte[] keyY) { this.keyY = keyY; }
	public void setKeyY(int i, byte b) { this.keyY[i] = b; }
	public void setTag(byte i, byte[] tag) { tags[i] = tag; }
	public void setMacKey(byte i, byte[] key) { keys[i] = key; }
	public int getX() { return ByteUtils.toUnsignedByte(x); }
	public byte[] getY() { return y; }
	public int getY(int i) { return ByteUtils.toUnsignedByte(y[i]); }
	public byte getType() { return type; }
	public int getOriginalLength() { return originalLength; }
	public byte[] getKeyY() { return keyY; }
	public byte[] getTag(byte i) { return tags[i]; }
	public byte[][] getTags() { return tags; }
	public byte[] getMacKey(byte i) { return keys[i]; }
	public byte[][] getMacKeys() { return keys; }
	
	@Override // just required for testing serialization
	public boolean equals(Object y) {
		if (this == y)
			return true;
		
		if (y == null)
			return false;
		
		if (!this.getClass().equals(y.getClass()))
			return false;
		
		Share that = (Share) y; // cast is guaranteed to succeed
		
		if (this.type != that.type)
			return false;
		if (this.x != that.x)
			return false;
		if (!Arrays.equals(this.y, that.y))
			return false;
		if (this.originalLength != that.originalLength)
			return false;
		if (!Arrays.equals(this.keyY, that.keyY))
			return false;
		if (!Arrays.deepEquals(this.tags, that.tags))
			return false;
		if (!Arrays.deepEquals(this.keys, that.keys))
			return false;
		
		return true;
	}
}