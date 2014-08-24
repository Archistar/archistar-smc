package at.archistar.crypto.data;

import java.nio.ByteBuffer;

import at.archistar.crypto.secretsharing.KrawczykCSS;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

/**
 * Represents a share for {@link KrawczykCSS}.
 * 
 * @author Elias Frantar
 * @version 2014-7-24
 */
public final class KrawczykShare extends BaseSerializableShare {
    
    /**
     * <p>Identifier for the algorithm used for encrypting the content of this share.</p>
     * 
     * Provides a method to get the corresponding Java-crypto-parameter-String for a identifier.
     */
    public static enum EncryptionAlgorithm {
        AES("AES/CBC/PKCS5Padding"),
        AES_GCM_256("AES/GCM/NoPadding");
        
        private final String algString;

        private EncryptionAlgorithm(String algString) { this.algString = algString; }
    
        public String getAlgString() { return algString; }
    }
    
    private final byte x;
    private final byte[] y;
    private final int originalLength;
    private final byte[] keyY;
    private final EncryptionAlgorithm alg;
    
    /**
     * Constructor
     * 
     * @param x the x-value (also identifier) of this share
     * @param y the y-values of this share
     * @param originalLength the original length of the shared data
     * @param keyY the y-values of the shared key
     * @param alg the algorithm used for encrypting the content
     * @throws NullPointerException if validation failed ({@link #validateShare()})
     */
    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public KrawczykShare(byte x, byte[] y, int originalLength, byte[] keyY, EncryptionAlgorithm alg) {
        this.x = x;
        this.y = y;
        this.originalLength = originalLength;
        this.keyY = keyY;
        this.alg = alg;
        
        validateShare();
    }
    
    /**
     * Constructor<br>
     * Tries to deserialize the serialized KrawczykShare.
     * 
     * @param serialized the serialized data (must be a valid serialized KrawczykShare)
     * @throws IllegalArgumentException if the given data was not a valid serialized share 
     *         ({@link BaseSerializableShare#validateSerialization(byte[], int)})
     * @throws NullPointerException if validation failed ({@link #validateShare()})
     */
    protected KrawczykShare(byte[] serialized) {
        validateSerialization(serialized, HEADER_LENGTH + 7); // + alg + originalLength + y.length + y + keyY
        
        ByteBuffer bb = ByteBuffer.wrap(serialized);
        bb.position(ID);
        
        /* deserialize x */
        x = bb.get();
        
        /* try to deserialize encryption algorithm */
        byte algOrdinal = bb.get();
        if (algOrdinal < 0 || algOrdinal > (EncryptionAlgorithm.values().length - 1)) {
            throw new IllegalArgumentException("encryption algorithm does not exist");
        }
        alg = EncryptionAlgorithm.values()[algOrdinal];
        
        /* deserialize originalLength */
        originalLength = bb.getInt();
        /* deserialize y.length */
        y = new byte[bb.getInt()];

        /* try to deserialize y */
        if (y.length < 1 || y.length > bb.remaining() - 1) {
            throw new IllegalArgumentException("invalid y-length field");
        }
        bb.get(y);
        
        /* deserialize keyY */
        keyY = new byte[bb.remaining()];
        bb.get(keyY);
        
        validateShare();
    }

    @Override
    public Algorithm getAlgorithm() {
        return Algorithm.KRAWCZYK;
    }
    
    @Override
    public int getId() {
        return x;
    }

    @Override
    protected byte[] serializeBody() {
        ByteBuffer bb = ByteBuffer.allocate(1 + 4 + 4 + y.length + keyY.length); // + alg + originalLength + y.length + y + keyY
        
        /* add encryption algorithm */
        bb.put((byte) alg.ordinal());
        /* add originalLength */
        bb.putInt(originalLength);
        /* add y.length */
        bb.putInt(y.length);
        
        /* add y-values */
        bb.put(y);
        /* add keyY */
        bb.put(keyY);
        
        return bb.array();
    }
    
    /**
     * Validates this share by checking if:
     * <ul>
     *  <li>x is not 0
     *  <li>y is not null
     *  <li>originalLength is larger than 0
     *  <li>keyY is not null
     *  <li>alg is not null
     * </ul>
     * @throws NullPointerException if any of the above conditions is violated
     */
    private void validateShare() {
        if (x == 0 || y == null || originalLength <= 0 || keyY == null || alg == null) {
            throw new NullPointerException();
        }
    }
    
    /* Getters */

    /* TODO: those two actually return a reference to the array, not
     *       sure that we want this security-wise, but performance
     *       might make this mandatory */
    @SuppressFBWarnings("EI_EXPOSE_REP")
    public byte[] getY() { return y; }
    @SuppressFBWarnings("EI_EXPOSE_REP")
    public byte[] getKeyY() { return keyY; }

    public int getOriginalLength() { return originalLength; }
    public EncryptionAlgorithm getEncryptionAlgorithm() { return alg; }
}
