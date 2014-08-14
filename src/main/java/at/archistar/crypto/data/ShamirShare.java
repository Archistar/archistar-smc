package at.archistar.crypto.data;

import java.nio.ByteBuffer;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import at.archistar.helper.ByteUtils;

/**
 * Represents a share for {@link ShamirPSS}.
 * 
 * @author Elias Frantar
 * @version 2014-7-24
 */
public final class ShamirShare extends BaseSerializableShare { // objects of this class should be immutable
    private final byte x;
    private final byte[] y;
    
    /**
     * Constructor
     * 
     * @param x the x-value (also identifier) of this share
     * @param y the y-values of this share
     * @throws NullPointerException if validation failed ({@link #validateShare()})
     */
    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public ShamirShare(byte x, byte[] y) {
        this.x = x;
        this.y = y;
        
        validateShare(); // catch invalid parameters
    }
    
    /**
     * Constructor<br>
     * Tries to deserialize the serialized ShamirShare.
     * 
     * @param serialized the serialized data (must be a valid serialized ShamirShare)
     * @throws IllegalArgumentException if the given data was not a valid serialized share 
     *         ({@link BaseSerializableShare#validateSerialization(byte[], int)})
     * @throws NullPointerException if validation failed ({@link #validateShare()})
     */
    protected ShamirShare(byte[] serialized) {
        validateSerialization(serialized, HEADER_LENGTH + 1); // + y
        
        ByteBuffer bb = ByteBuffer.wrap(serialized);
        bb.position(ID);
        
        /* deserialize x */
        x = bb.get();
        
        /* deserialize y */
        y = new byte[bb.remaining()];
        bb.get(y);
        
        validateShare(); // catch invalid parameters
    }
    
    @Override
    public Algorithm getAlgorithm() {
        return Algorithm.SHAMIR;
    }

    @Override
    public int getId() {
        return ByteUtils.toUnsignedByte(x);
    }
    
    @Override
    protected byte[] serializeBody() {
        return y;
    }
    
    /**
     * Validates this share by checking if:
     * <ul>
     *  <li>x is not 0
     *  <li>y is not null
     * </ul>
     * @throws NullPointerException if any of the above conditions is violated
     */
    private void validateShare() {
        if (x == 0 || y == null) { // x cannot be < 0 because it is an unsigned byte
            throw new NullPointerException();
        }
    }
    
    /* Getters */
    /* TODO: security vs performance */
    @SuppressFBWarnings("EI_EXPOSE_REP")
    public byte[] getY() { return y; }
}
