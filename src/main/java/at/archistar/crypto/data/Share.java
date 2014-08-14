package at.archistar.crypto.data;

/**
 * The base interface of a share defining the absolutely necessary methods.
 * 
 * @author Elias Frantar
 * @version 2014-7-22
 */
public interface Share {
    
    /**
     * Identifier for the algorithm used to create this share.
     */
    public static enum Algorithm {
        SHAMIR,
        REED_SOLOMON,
        KRAWCZYK,
        RABIN_BEN_OR
    }
    
    /**
     * Returns the identifier of the algorithm used for creating this share.
     * @return the algorithm used for creating this share
     */
    public Algorithm getAlgorithm();
    
    /**
     * Returns the identifier (the x-value) of this share.
     * @return the x-value of this share (an unsigned byte in range 0 - 255)
     */
    public int getId();
    
    /**
     * Serializes the share.
     * @return the serialized share (in bytes)
     */
    public byte[] serialize();
}
