package at.archistar.crypto.data;

import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.informationchecking.CevallosUSRSS;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Represents a share for {@link RabinBenOrVSS} and {@link CevallosUSRSS}.
 */
public class VSSShare extends SerializableShare {
    private final SerializableShare share;
    private final Map<Byte, byte[]> macs;
    private final Map<Byte, byte[]> macKeys;
    
    /**
     * Constructor
     * 
     * @param share the underlying share
     * @param macs a map containing the macs of the underlying share identified by the share-ids
     * @param macKeys a map containing the macKeys of the underlying share identified by the share-ids
     * @throws WeakSecurityException if validation failed ({@link #validateShare()})
     */
    public VSSShare(SerializableShare share, Map<Byte, byte[]> macs, Map<Byte, byte[]> macKeys) throws WeakSecurityException {
        
        this.share = share;
        this.macs = macs;
        this.macKeys = macKeys;
        
        if (!isValid()) {
            throw new NullPointerException();
        }
    }
    
    public VSSShare(SerializableShare share) throws WeakSecurityException {
        this.share = share;
        this.macs = new HashMap<>();
        this.macKeys = new HashMap<>();
    }

    @Override
    public void serializeBody(DataOutputStream os) throws IOException {

        /* serialize macs */
        os.writeInt(macs.size());
        for (Map.Entry<Byte, byte[]> e : macs.entrySet()) {
            Byte id = e.getKey();
            byte[] mac = e.getValue();
            
            os.writeByte(id);
            os.writeInt(mac.length);
            os.write(mac);
        }
        
        /* serialize keys */
        os.writeInt(macKeys.size());
        for (Map.Entry<Byte, byte[]> e : macKeys.entrySet()) {
            Byte id = e.getKey();
            byte[] mac = e.getValue();
            
            os.writeByte(id);
            os.writeInt(mac.length);
            os.write(mac);
        }
        
        /* serialize share */
        os.writeByte((byte)share.getAlgorithm().ordinal());
        share.serializeBody(os);
    }

    @Override
    public int getId() {
        return share.getId();
    }
    
    public Share getShare() {
        return this.share;
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
    @SuppressFBWarnings("DB_DUPLICATE_SWITCH_CLAUSES")
    public static VSSShare deserialize(DataInputStream in, int version, byte x) throws IOException, WeakSecurityException {
        
        /* deserialize macs */
        int macCount = in.readInt();
        Map<Byte, byte[]> macs = new HashMap<>();
        for (int i = 0; i < macCount; i++) {
            byte id = in.readByte();
            int length = in.readInt();
            byte[] mac = new byte[length];
            assert in.read(mac) == length;
            macs.put(id, mac);
        }
        
        /* deserialize keys */
        macCount = in.readInt();
        Map<Byte, byte[]> macKeys = new HashMap<>();
        for (int i = 0; i < macCount; i++) {
            byte id = in.readByte();
            int length = in.readInt();
            byte[] mac = new byte[length];
            assert in.read(mac) == length;
            macKeys.put(id, mac);
        }
        
        /* deserialize the share */
        byte algByte = in.readByte();
        Algorithm alg = Algorithm.values()[algByte];
        
        SerializableShare share;
        switch(alg) {
        case SHAMIR:
            share = ShamirShare.deserialize(in, version, x);
            break;
        case REED_SOLOMON:
            share = ReedSolomonShare.deserialize(in, version, x);
            break;
        case KRAWCZYK:
            share =  KrawczykShare.deserialize(in, version, x);
            break;
        case RABIN_BEN_OR:
            share = VSSShare.deserialize(in, version, x);
            break;
        case CEVALLOS:
            share = VSSShare.deserialize(in, version, x);
            break;
        default:
            throw new IllegalArgumentException("no matching sharetype");
        }
        
        return new VSSShare(share, macs, macKeys);
    }
    
    @Override
    public Algorithm getAlgorithm() {
        return Algorithm.RABIN_BEN_OR;
    }
    
    /**
     * Validates this share by checking if:
     * <ul>
     *  <li>share is not null
     *  <li>share is either a ShamirShare or a KrawczykShare
     *  <li>macs is not null
     *  <li>macKeys is not null
     *  <li>all macs-values have the same length
     *  <li>all macKeys have the same length
     * </ul>
     * @return true if share is valid
     */
    @Override
    public boolean isValid() {
        if (share == null || macs == null || macKeys == null) { // catch invalid parameters
            return false;
        }

        if (!(share.getAlgorithm() == Algorithm.SHAMIR || share.getAlgorithm() == Algorithm.KRAWCZYK)) { // underlying share may only be a Shamir or a Krawczyk one
            return false;
        }
        
        /* check if all macs are of equal length */
        int firstLength = -1; 
        for (byte[] mac : macs.values()) {
            if (firstLength == -1 && mac != null) {
                firstLength = mac.length;
            }
            if (mac == null || mac.length != firstLength) {
                return false;
            }
        }
        /* check if all macKeys are of equal length */
        firstLength = -1; 
        for (byte[] macKey : macKeys.values()) {
            if (firstLength == -1 && macKey != null) {
                firstLength = macKey.length;
            }
            if (macKey == null || macKey.length != firstLength) {
                return false;
            }
        }
        return true;
    }
    
    /* Getters */
    public Map<Byte, byte[]> getMacs() { return macs; }
    public Map<Byte, byte[]> getMacKeys() { return macKeys; }
    
    public static SerializableShare[] getInnerShares(VSSShare shares[]) {
        SerializableShare[] result = new SerializableShare[shares.length];
        for (int i = 0; i < shares.length; i++) {
            result[i] = (SerializableShare)shares[i].getShare();
        }
        return result;
    }
}
