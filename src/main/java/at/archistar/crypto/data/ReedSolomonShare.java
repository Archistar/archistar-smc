package at.archistar.crypto.data;

import java.nio.ByteBuffer;

import at.archistar.helper.ByteUtils;

/**
 * Represents a share for {@link RabinIDS}.
 * 
 * @author Elias Frantar
 * @version 2014-7-24
 */
public final class ReedSolomonShare extends BaseSerializableShare {
	private final byte x;
	private final byte[] y;
	private final int originalLength;
	
	/**
	 * Constructor
	 * 
	 * @param x the x-value (also identifier) of this share
	 * @param y the y-values of this share
	 * @param originalLength the original length of the shared data
	 * @throws NullPointerException if validation failed ({@link #validateShare()})
	 */
	public ReedSolomonShare(byte x, byte[] y, int originalLength) {
		this.x = x;
		this.y = y;
		this.originalLength = originalLength;
		
		validateShare();
	}
	
	/**
	 * Constructor<br>
	 * Tries to deserialize the serialized ReedSolomonShare.
	 * 
	 * @param serialized the serialized data (must be a valid serialized ReedSolomonShare)
	 * @throws IllegalArgumentException if the given data was not a valid serialized share 
	 * 		   ({@link BaseSerializableShare#validateSerialization(byte[], int)})
	 * @throws NullPointerException if validation failed ({@link #validateShare()})
	 */
	protected ReedSolomonShare(byte[] serialized) {
		validateSerialization(serialized, HEADER_LENGTH + 5); // + y + originalLength.length
		
		ByteBuffer bb = ByteBuffer.wrap(serialized);
		bb.position(ID);
		
		/* deserialize x */
		x = bb.get();
		
		/* deserialize originalLength */
		originalLength = bb.getInt();
		
		/* deserialize y */
		y = new byte[bb.remaining()];
		bb.get(y);
		
		validateShare();
	}

	@Override
	public Algorithm getAlgorithm() {
		return Algorithm.REED_SOLOMON;
	}

	@Override
	public int getId() {
		return ByteUtils.toUnsignedByte(x);
	}

	@Override
	protected byte[] serializeBody() {
		ByteBuffer bb = ByteBuffer.allocate(4 + y.length);
		
		/* add originalLength */
		bb.putInt(originalLength);
		
		/* add the y-values */
		bb.put(y);
		
		return bb.array();
	}
	
	/**
	 * Validates this share by checking if:
	 * <ul>
	 * 	<li>x is not 0
	 * 	<li>y is not null
	 * 	<li>originalLength is larger than 0
	 * </ul>
	 * @throws NullPointerException if any of the above conditions is violated
	 */
	private void validateShare() {
		if (x == 0 || y == null || originalLength <= 0) {
			throw new NullPointerException();
		}
	}
	
	/* Getters */
	public byte[] getY() { return y; }
	public int getOriginalLength() { return originalLength; }
}
