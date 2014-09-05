package at.archistar.crypto.data;

import at.archistar.crypto.data.Share.Algorithm;
import at.archistar.crypto.secretsharing.KrawczykCSS;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 * Represents a share for {@link KrawczykCSS}.
 */
public final class KrawczykShare extends BaseShare implements Comparable<KrawczykShare>{

    @Override
    public int compareTo(KrawczykShare t) {
        if (t.getId() == getId() && Arrays.equals(t.getY(), getY()) &&
                t.getOriginalLength() == getOriginalLength() &&
                Arrays.equals(t.getKeyY(), getKeyY())) {
            return 0;
        } else {
            return t.getId() - getId();
        }
    }

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
     * @throws InvalidParametersException if validation failed ({@link #validateShare()})
     */
    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public KrawczykShare(byte x, byte[] y, int originalLength, byte[] keyY, EncryptionAlgorithm alg) throws InvalidParametersException {
        super(x, y);
        this.originalLength = originalLength;
        this.keyY = keyY;
        this.alg = alg;
        
        if (!isValid()) {
            throw new InvalidParametersException();
        }
    }
    
    /**
     * Tries to de-serialize a serialized Share.
     * 
     * @param in the serialized data
     * @param version the expected version (as read from the header)
     * @param x the xValue/key of the share
     * @return the de-serialized share
     * @throws IOException in case share wasn't deserializable
     */
    public static KrawczykShare deserialize(DataInputStream in, int version, byte x) throws IOException, InvalidParametersException {

        byte algOrdinal = in.readByte();
        if (algOrdinal < 0 || algOrdinal > (EncryptionAlgorithm.values().length - 1)) {
            throw new IllegalArgumentException("encryption algorithm does not exist");
        }
        EncryptionAlgorithm alg = EncryptionAlgorithm.values()[algOrdinal];

        int originalLength = in.readInt();
        int yLength = in.readInt();
        
        byte[] tmpY = new byte[yLength];
        assert in.read(tmpY) == yLength;
        
        int keyYLength = in.readInt();
        
        byte[] tmpYKey = new byte[keyYLength];
        assert in.read(tmpYKey) == keyYLength;
        
        return new KrawczykShare(x, tmpY, originalLength, tmpYKey, alg);
    }

    @Override
    public Algorithm getAlgorithm() {
        return Algorithm.KRAWCZYK;
    }
    
    @Override
    public void serializeBody(DataOutputStream os) throws IOException {
        os.writeByte((byte) alg.ordinal());
        os.writeInt(originalLength);
        os.writeInt(y.length);
        os.write(y);
        os.writeInt(keyY.length);
        os.write(keyY);
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
     * @return true if share is valid
     */
    @Override
    public boolean isValid() {
        return !(x == 0 || y == null || originalLength <= 0 || keyY == null || alg == null);
    }
    
    /* TODO: those two actually return a reference to the array, not
     *       sure that we want this security-wise, but performance
     *       might make this mandatory */
    @SuppressFBWarnings("EI_EXPOSE_REP")
    public byte[] getKeyY() {
        return keyY;
    }

    public int getOriginalLength() {
        return originalLength;
    }
    
    public EncryptionAlgorithm getEncryptionAlgorithm() {
        return alg;
    }
    
    @Override
    public boolean equals(Object o) {
        if (o instanceof KrawczykShare) {
            return compareTo((KrawczykShare)o) == 0;
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        assert false : "hashCode not designed";
        return 42;
    }

}
