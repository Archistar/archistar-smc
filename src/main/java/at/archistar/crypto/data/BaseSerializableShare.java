package at.archistar.crypto.data;

import java.nio.ByteBuffer;

/**
 * Abstract base class of all serializable shares implementing the serialization core.
 * 
 * @author Elias Frantar
 * @version 2014-7-24
 */
public abstract class BaseSerializableShare extends BaseShare {
    public static final int VERSION = 1;
    
    public static final int HEADER_LENGTH = 10; // bytes
    
    /* the locations of specific fields in the header */
    public static final int VERSION_START = 0;
    public static final int VERSION_END = 3;
    public static final int ALGORITHM = 4;
    public static final int LENGTH_START = 5;
    public static final int LENGTH_END = 8;
    public static final int ID = 9;
    
    @Override
    public byte[] serialize() {
        byte[] header = serializeHeader();
        byte[] body = serializeBody();
        
        ByteBuffer bb = ByteBuffer.allocate(header.length + body.length);
        
        /* append body to header in a single array */
        bb.put(header);
        bb.put(body);
        
        /* add the length of the share */
        bb.putInt(LENGTH_START, bb.capacity());
        
        return bb.array();
    }
    
    /**
     * Serializes the header of the share.<br>
     * The header always consists of: <i>algorithm (1 byte) || length of serialized share (4 bytes) || share id / x (1 byte) </i>
     * @return the serialized header of a share
     */
    protected byte[] serializeHeader() {
        ByteBuffer bb = ByteBuffer.allocate(HEADER_LENGTH);
        
        /* serialize header */
        bb.putInt(VERSION);
        
        /* serialize algorithm */
        bb.put((byte) getAlgorithm().ordinal());
        
        /* leave [LENGTH_START] - [LENGTH_END] empty to add the length later on */
        bb.putInt(0);
        
        /* serialize the x-value */
        bb.put((byte) getId());
        
        return bb.array();
    }
    /**
     * Serializes the body of the share.<br>
     * The contents of the body are share-type specific.
     * @return the serialized body of the share
     */
    protected abstract byte[] serializeBody();
    
    /**
     * Validates the serialized share (by checking the header information) for the following criteria:
     * <ul>
     *  <li>is not null
     *  <li>is larger than <i>minLength</i>
     *  <li>version equals VERSION
     *  <li>algorithm equals {@link #getAlgorithm()}
     *  <li>length equals {@code serialized.length}
     * </ul>
     * 
     * @param serialized the serialized share to check
     * @param minLength the minimum length the serialized share is allowed to have
     * @throws IllegalArgumentException if any of the above conditions is violated
     */
    protected void validateSerialization(byte[] serialized, int minLength) {
        /* check if serialized share is long enough to even be verified */
        if (serialized == null || serialized.length < minLength) {
            throw new IllegalArgumentException("data too short");
        }
        
        ByteBuffer bb = ByteBuffer.wrap(serialized);
        
        /* check version */
        if (bb.getInt() != VERSION) {
            throw new IllegalArgumentException("version mismatch");
        }
        /* check algorithm */
        if (bb.get() != getAlgorithm().ordinal()) {
            throw new IllegalArgumentException("algorithm mismatch");
        }
        /* check length */
        if (bb.getInt() != serialized.length) {
            throw new IllegalArgumentException("length-field does not equal data-length");
        }
    }
}
