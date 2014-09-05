package at.archistar.crypto.data;

import at.archistar.crypto.exceptions.WeakSecurityException;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
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
    public static Share deserialize(byte[] serialized) throws IOException, WeakSecurityException, InvalidParametersException {
        
        if (serialized == null) {
            throw new InvalidParametersException("how should you deserialize from null?");
        }
        
        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        DataInputStream is = new DataInputStream(bis);

        Algorithm alg = null;
        int version = -1;
        byte x = -1;
        
        try {
            version = is.readInt();

            if (version != VERSION) {
                throw new InvalidParametersException("Different on-disk format verson");
            }

            byte algByte = is.readByte();
            if (algByte >= 0 && algByte < Algorithm.values().length) {
                alg = Algorithm.values()[algByte];
                x = (byte)is.readInt();
            } else {
                throw new InvalidParametersException("unknown share type");
            }
        } catch (IOException ex) {
            throw new InvalidParametersException("invalid on-disk format: " + ex.getMessage());
        }

        Share share = null;
        switch(alg) {
        case SHAMIR:
            share =  ShamirShare.deserialize(is, version, x);
            break;
        case REED_SOLOMON:
            share = ReedSolomonShare.deserialize(is, version, x);
            break;
        case KRAWCZYK:
            share = KrawczykShare.deserialize(is, version, x);
            break;
        case RABIN_BEN_OR:
            share = VSSShare.deserialize(is, version, x);
            break;
        case CEVALLOS:
            share = VSSShare.deserialize(is, version, x);
            break;
        default:
            throw new InvalidParametersException("no matching sharetype");
        }

        // check for EOF
        try {
            is.readByte();
            throw new InvalidParametersException("data was too long");
        } catch (EOFException ex) {
            // this is actually the good case
        }
        
        return share;
    }
}
