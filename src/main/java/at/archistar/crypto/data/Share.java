package at.archistar.crypto.data;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * @author andy
 */
public class Share implements Comparable<Share> {
    
    private final byte id;
    
    private final byte[] yValues;
    
    private final Map<Byte, byte[]> metadata;
    
    private final Map<Byte, byte[]> macKeys;
    
    private final Map<Byte, byte[]> macs;
    
    private final ShareType shareType;
    
    private ICType informationChecking;
    
    public static final int VERSION = 3;
    
    /** which share types can we work with? */
    public static enum ShareType {
        SHAMIR,
        REED_SOLOMON,
        KRAWCZYK,
        NTT_SHAMIR,
        NTT_REED_SOLOMON
    }
    
    /** which information checking schemas can we work with? */
    public static enum ICType {
        NONE,
        RABIN_BEN_OR,
        CEVALLOS        
    }
    
    public static final byte ORIGINAL_LENGTH = 1;
    
    public static final byte ENC_ALGORITHM = 2;
    
    public static final byte ENC_KEY = 3;
    
    public static final byte NTT_SHARE_SIZE = 4;

    @SuppressFBWarnings("EI_EXPOSE_REP2")
    Share(ShareType shareType, byte id, byte[] body, Map<Byte, byte[]> metadata, ICType ic, Map<Byte, byte[]> macKeys, Map<Byte, byte[]> macs) {
        this.id = id;
        this.yValues = body;
        this.metadata = metadata;
        this.shareType = shareType;
        this.macs = macs;
        this.macKeys = macKeys;
        this.informationChecking = ic;
    }
    
    @SuppressFBWarnings("EI_EXPOSE_REP2")
    Share(ShareType shareType, byte id, byte[] body, Map<Byte, byte[]> metadata) {
        this(shareType, id, body, metadata, ICType.NONE, new HashMap<Byte, byte[]>(), new HashMap<Byte, byte[]>());
    }

    public void setInformationChecking(ICType icType) {
        this.informationChecking = icType;
    }

    public int getX() {
        return id;
    }
    
    public byte getId() {
        return id;
    }
    
    @SuppressFBWarnings("EI_EXPOSE_REP")
    public byte[] getYValues() {
        return yValues;
    }
    
    protected byte[] getBody() throws IOException {
        return yValues;
    }
    
    public byte[] getSerializedForHashing() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        DataOutputStream sout = new DataOutputStream(out);
        
        sout.writeInt(VERSION);
        sout.writeByte((byte) shareType.ordinal());
        sout.writeByte((byte) informationChecking.ordinal());
        
        /* serialize the x-value */
        sout.writeByte((byte)getId());
        
        /* write metadata */
        writeMap(sout, metadata);
        
        /* serialize body */
        sout.writeInt(yValues.length);
        sout.write(yValues);
        
        return out.toByteArray();
    }
    
    private static void writeMap(DataOutputStream sout, Map<Byte, byte[]> map) throws IOException {
        sout.writeInt(map.size());
        for (Map.Entry<Byte, byte[]> e : map.entrySet()) {
            Byte key = e.getKey();
            byte[] value = e.getValue();
            
            sout.writeByte(key);
            sout.writeInt(value.length);
            sout.write(value);
        }
    }
    
    public byte[] serialize() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        DataOutputStream sout = new DataOutputStream(out);
        
        /* serialize main data */
        sout.write(getSerializedForHashing());
        
        if (informationChecking != ICType.NONE) {
            /* serialize macs */
            writeMap(sout, macs);
        
            /* serialize keys */
            writeMap(sout, macKeys);
        }
        
        return out.toByteArray();
    }
    
    public int getMetadata(int key) {
        byte[] tmp = this.metadata.get((byte)key);
        if (tmp.length == 4) {
            return ByteBuffer.wrap(tmp).getInt();
        } else {
            throw new RuntimeException("this cannot happen, key not found!");
        }
    }
    
    public byte[] getMetadataArray(int key) {
        return this.metadata.get((byte)key);
    }
    
    public Map<Byte, byte[]> getMacs() {
        return this.macs;
    }
    
    public Map<Byte, byte[]> getMacKeys() {
        return this.macKeys;
    }
    
    public boolean isValid() {
        
        if (id <= 0 || yValues == null || metadata == null) {
            return false;
        }
        
        boolean result = true;
        
        if (shareType == ShareType.SHAMIR) {
            //no additional checks needed
        } else if (shareType == ShareType.KRAWCZYK) {
            result = metadata.containsKey(ENC_ALGORITHM) && metadata.containsKey(ORIGINAL_LENGTH) && metadata.containsKey(ENC_KEY);
        } else if (shareType == ShareType.REED_SOLOMON) {
            result = metadata.containsKey((byte)1);            
        } else if (shareType == ShareType.NTT_REED_SOLOMON || shareType == ShareType.NTT_SHAMIR) {
            result = metadata.containsKey(ORIGINAL_LENGTH) &&
                     metadata.containsKey(NTT_SHARE_SIZE);            
        } else {
            throw new RuntimeException("impossible: unknown algorithm");
        }
        
        switch (informationChecking) {
            case NONE:
                break;
            case RABIN_BEN_OR:
            case CEVALLOS:
                result = !(macKeys == null || macs == null);
                /* todo: check if enough macs & keys exist */
                break;
            default:
                throw new RuntimeException("impossible: unknown algorithm");            
        }
        return result;
    }
    
    @Override
    public int compareTo(Share t) {
        
        try {
            if (Arrays.equals(serialize(), t.serialize())) {
                return 0;
            } else {
                return t.id - id;
            }
        } catch (IOException ex) {
            return t.id - id;
        }
    }
    
    @Override
    public boolean equals(Object o) {
        if (o instanceof Share) {
            return ((Share)o).compareTo(this) == 0;
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
