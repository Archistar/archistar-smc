package at.archistar.crypto.data;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import at.archistar.crypto.exceptions.ImpossibleException;
import at.archistar.crypto.exceptions.WeakSecurityException;

/**
 * Represents a share for {@link RabinBenOrVSS}.
 * 
 * @author Elias Frantar
 * @version 2014-7-24
 */
public class RabinBenOrShare extends BaseSerializableShare {
	private Share share;
	private Map<Byte, byte[]> macs;
	private Map<Byte, byte[]> macKeys;
	
	/**
	 * Constructor
	 * 
	 * @param share the underlying share
	 * @param macs a map containing the macs of the underlying share identified by the share-ids
	 * @param macKeys a map containing the macKeys of the underlying share identified by the share-ids
	 * @throws NullPointerException if validation failed ({@link #validateShare()})
	 */
	public RabinBenOrShare(Share share, Map<Byte, byte[]> macs, Map<Byte, byte[]> macKeys) throws WeakSecurityException {
		this.share = share;
		this.macs = macs;
		this.macKeys = macKeys;
		
		validateShare();
	}
	
	/**
	 * Constructor<br>
	 * Tries to deserialize the serialized RabinBenOrShare.
	 * 
	 * @param serialized the serialized data (must be a valid serialized RabinBenOrShare)
	 * @throws IllegalArgumentException if the given data was not a valid serialized share 
	 * 		   ({@link BaseSerializableShare#validateSerialization(byte[], int)})
	 * @throws NullPointerException if validation failed ({@link #validateShare()})
	 */
	public RabinBenOrShare(byte[] serialized) {
		validateSerialization(serialized, HEADER_LENGTH + 2*(4 + 4 + 2) + 11); // + macs + macKeys + share
		
		ByteBuffer bb = ByteBuffer.wrap(serialized); // cut off the header
		bb.position(ID + 1); // x is saved redundantly when using Rabin-Ben-Or
		
		/* deserialize macs */
		macs = new HashMap<Byte, byte[]>();
		
		int size = bb.getInt();
		byte key;
		byte[] value = new byte[bb.getInt()]; // value-size
		for (int i = 0; i < size; i++) {
			key = bb.get();
			bb.get(value);
			
			macs.put(key, Arrays.copyOf(value, value.length)); // we may not pass references to the Map
		}
		
		/* deserialize macKeys */
		macKeys = new HashMap<Byte, byte[]>();
		
		size = bb.getInt();
		value = new byte[bb.getInt()]; // value-size
		for (int i = 0; i < size; i++) {
			key = bb.get();
			bb.get(value);
			
			macKeys.put(key, Arrays.copyOf(value, value.length));
		}
		
		/* deserialize the share */
		byte[] sShare = new byte[bb.remaining()];
		bb.get(sShare);
		share = ShareDeserializer.deserialize(sShare);
	}
	
	@Override
	public Algorithm getAlgorithm() {
		return Algorithm.RABIN_BEN_OR;
	}

	@Override
	public int getId() {
		return share.getId();
	}

	@Override
	protected byte[] serializeBody() {
		try {
        	ByteArrayOutputStream bos = new ByteArrayOutputStream();
        	
        	/* serialize macs */
        	bos.write(ByteBuffer.allocate(4).putInt(macs.size()).array()); // size
        	bos.write(ByteBuffer.allocate(4).putInt(macs.get(macs.keySet().toArray()[0]).length).array()); // value size
        	
        	for (byte key : macs.keySet()) {
        		bos.write(new byte[]{key}); // key
        		bos.write(macs.get(key)); // value
        	}
        	
        	/* serialize macKeys */
        	bos.write(ByteBuffer.allocate(4).putInt(macKeys.size()).array()); // size
        	bos.write(ByteBuffer.allocate(4).putInt(macKeys.get(macKeys.keySet().toArray()[0]).length).array()); // value size
        	
        	for (byte key : macKeys.keySet()) {
        		bos.write(new byte[]{key}); // key
        		bos.write(macKeys.get(key)); // value
        	}
        	
        	/* serialize underlying share */
        	bos.write(share.serialize());
        	
        	return bos.toByteArray();
		} catch (Exception e) { // this should never happen
			throw new ImpossibleException("serializing failed");
		}
	}
	
	/**
	 * Validates this share by checking if:
	 * <ul>
	 * 	<li>share is not null
	 * 	<li>share is either a ShamirShare or a KrawczykShare
	 * 	<li>macs is not null
	 * 	<li>macKeys is not null
	 * 	<li>all macs-values have the same length
	 * 	<li>all macKeys have the same length
	 * </ul>
	 * @throws WeakSecurityException if share is not a ShamirShare or a KrawczykShare
	 * @throws NullPointerException if any of the other above conditions is violated
	 */
	private void validateShare() throws WeakSecurityException {
		if (!(share.getAlgorithm() == Algorithm.SHAMIR || share.getAlgorithm() == Algorithm.KRAWCZYK)) { // underlying share may only be a Shamir or a Krawczyk one
			throw new WeakSecurityException();
		}
		if (share == null || macs == null || macKeys == null) { // catch invalid parameters
			throw new NullPointerException();
		}
		
		/* check if all macs are of equal length */
		int firstLength = -1; 
		for (byte[] mac : macs.values()) {
			if (firstLength == -1 && mac != null) {
				firstLength = mac.length;
			}
			if (mac == null ||mac.length != firstLength) {
				throw new NullPointerException();
			}
		}
		/* check if all macKeys are of equal length */
		firstLength = -1; 
		for (byte[] macKey : macKeys.values()) {
			if (firstLength == -1 && macKey != null) {
				firstLength = macKey.length;
			}
			if (macKey == null ||macKey.length != firstLength) {
				throw new NullPointerException();
			}
		}
	}
	
	/* Getters */
	public Share getShare() { return share; }
	public Map<Byte, byte[]> getMacs() { return macs; }
	public Map<Byte, byte[]> getMacKeys() { return macKeys; }
}
