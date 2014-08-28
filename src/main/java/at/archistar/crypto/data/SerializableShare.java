package at.archistar.crypto.data;

import at.archistar.crypto.exceptions.WeakSecurityException;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

/**
 *
 * @author andy
 */
public abstract class SerializableShare implements Share {
    
    public abstract void serializeBody(DataOutputStream os) throws IOException;
    
    public static final int VERSION = 2;

    @Override
    public byte[] serialize() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        DataOutputStream sout = new DataOutputStream(out);
        
        sout.writeInt(VERSION);
        sout.writeByte((byte) getAlgorithm().ordinal());
        
        /* serialize the x-value */
        sout.writeInt((byte)getId());
        
        serializeBody(sout);
        
        return out.toByteArray();
    }
    
    @SuppressFBWarnings("DB_DUPLICATE_SWITCH_CLAUSES")
    public static Share deserialize(byte[] serialized) throws IOException, WeakSecurityException {
        
        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        DataInputStream is = new DataInputStream(bis);
        
        int version = is.readInt();
        assert(version == 2);
        
        byte algByte = is.readByte();
        Algorithm alg = Algorithm.values()[algByte];
        
        byte x = (byte)is.readInt();
        
        switch(alg) {
        case SHAMIR:
            return ShamirShare.deserialize(is, version, x);
        case REED_SOLOMON:
            return ReedSolomonShare.deserialize(is, version, x);
        case KRAWCZYK:
            return KrawczykShare.deserialize(is, version, x);
        case RABIN_BEN_OR:
            return VSSShare.deserialize(is, version, x);
        case CEVALLOS:
            return VSSShare.deserialize(is, version, x);
        default:
            throw new IllegalArgumentException("no matching sharetype");
        }
    }
}
