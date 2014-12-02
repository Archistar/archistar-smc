package at.archistar.crypto.data;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author andy
 */
public class KrawczykShare extends Share {
    
    public static final byte KEY_ORIGINAL_LENGTH = 1;
    
    public static final byte KEY_ENC_ALGORITHM = 2;
    
    private final byte[] key;

    @SuppressFBWarnings("EI_EXPOSE_REP2")
    KrawczykShare(byte id, byte[] key, byte[] share, Map<Byte, Integer> metadata, ICType ic, Map<Byte, byte[]> macKeys, Map<Byte, byte[]> macs) throws InvalidParametersException {
        super(ShareType.KRAWCZYK, id, share, metadata, ic, macKeys, macs);
        this.key = key;
    }

    KrawczykShare(byte id, byte[] key, byte[] yVals, Map<Byte, Integer> metadata) {
        super(ShareType.KRAWCZYK, id, yVals, metadata, ICType.NONE, new HashMap<Byte, byte[]>(), new HashMap<Byte, byte[]>());
        this.key = key;
    }
    
    @SuppressFBWarnings("EI_EXPOSE_REP")
    public byte[] getKey() {
        return this.key;
    }
    
    @Override
    protected byte[] getBody() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        DataOutputStream sout = new DataOutputStream(out);
        
        sout.writeInt(yValues.length);
        sout.writeInt(key.length);
        sout.write(yValues);
        sout.write(key);
        
        return out.toByteArray();
    }
    
    @Override
    public boolean isValid() {
        return super.isValid() && key != null &&  metadata.containsKey(KEY_ENC_ALGORITHM) && metadata.containsKey(KEY_ORIGINAL_LENGTH);
    }
    
    @Override
    public int compareTo(Share t) {
        int parentResult = super.compareTo(t);
        
        if (parentResult == 0) {
            /* this actually must be the case! */
            if (t instanceof KrawczykShare) {
                if (Arrays.equals(key, ((KrawczykShare)t).key)) {
                    return 0;
                } else {
                    return t.id - id;
                }
            } else {
                throw new RuntimeException("how can this even be?");
            }
        } else {
            return parentResult;
        }
    }
    
    @Override
    @SuppressFBWarnings("EQ_OVERRIDING_EQUALS_NOT_SYMMETRIC")
    public boolean equals(Object o) {
        if (o instanceof KrawczykShare) {
            return ((KrawczykShare)o).compareTo(this) == 0;
        } else {
            return false;
        }
    }
    
    @Override
    public int hashCode() {
        assert false : "hashCode not implemented";
        return 42;
    }
}
