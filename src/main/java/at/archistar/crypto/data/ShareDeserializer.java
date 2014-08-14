package at.archistar.crypto.data;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import at.archistar.crypto.data.Share.Algorithm;

/**
 * This class provides utility do deserialize a serialized {@link Share}.
 * 
 * @author Elias Frantar
 * @version 2014-7-23
 */
public class ShareDeserializer {
    private ShareDeserializer() {} // just remove the constructor-field from javadoc
    
    /**
     * Attempts to deserialize the given serialized {@link Share}.
     * 
     * @param serialized the serialized share
     * @return the deserialized share
     * @throws IllegalArgumentException if the given share could not be deserialized properly
     */
    @SuppressFBWarnings("DB_DUPLICATE_SWITCH_CLAUSES")
    public static Share deserialize(byte[] serialized) {
        switch(Algorithm.values()[serialized[BaseSerializableShare.ALGORITHM]]) {
            case SHAMIR:
                return new ShamirShare(serialized);
            case REED_SOLOMON:
                return new ReedSolomonShare(serialized);
            case KRAWCZYK:
                return new KrawczykShare(serialized);
            case RABIN_BEN_OR:
                return new KrawczykShare(serialized);
            default:
                throw new IllegalArgumentException("no matching sharetype");
        }
    }
}
