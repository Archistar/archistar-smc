package at.archistar.crypto.data;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Represent a Share in memory (including metadata and information checking
 * information). Shares are always created by the ShareFactory helper class.
 */
public abstract class Share implements Comparable<Share> {

    /** the share's id, mostly this will be it's "x" value */
    private final byte id;

    /** the share's body, mostly this will be it's "y" values */
    private final byte[] yValues;

    /** keys used during information checking */
    private final Map<Byte, byte[]> macKeys;

    /** macs generated during information checking */
    private final Map<Byte, byte[]> macs;

    /** which kind of information checking (if any) was employed? */
    private ICType informationChecking;

    /** on-disk version of the share */
    public static final int VERSION = 4;

    /** which information checking schemas can we work with? */
    public enum ICType {
        /** no information checking was performed */
        NONE,
        /** rabin-ben-or with fixed hashes */
        RABIN_BEN_OR,
        /** cevallos with dynamic length hashes */
        CEVALLOS
    }

    /**
     * Constructor with information checking information.
     *
     * @param id the share's id (i.e. x value)
     * @param body the share's body (i.e. y values)
     * @param ic the information checking algorithm used by the share
     * @param macKeys the mac keys used for information checking
     * @param macs the macs generated during information checking
     */
    @SuppressFBWarnings("EI_EXPOSE_REP2")
    Share(byte id, byte[] body, ICType ic, Map<Byte, byte[]> macKeys, Map<Byte, byte[]> macs) throws InvalidParametersException {
        if (id == 0) {
            throw new InvalidParametersException("id must not be 0");
        }
        if (body == null || body.length == 0) {
            throw new InvalidParametersException("body must not be empty");
        }
        this.id = id;
        this.yValues = body;
        this.macs = macs;
        this.macKeys = macKeys;
        this.informationChecking = ic;
    }

    /**
     * Constructor without information checking
     *
     * @param id the share's id (i.e. x value)
     * @param body the share's body (i.e. y values)
     */
    Share(byte id, byte[] body) throws InvalidParametersException {
        if (id == 0) {
            throw new InvalidParametersException("id must not be 0");
        }
        if (body == null || body.length == 0) {
            throw new InvalidParametersException("body must not be empty");
        }
        this.id = id;
        this.yValues = body;
        this.macs = new HashMap<>();
        this.macKeys = new HashMap<>();
        this.informationChecking = ICType.NONE;
    }

    /**
     * set the used information checking algorithm
     *
     * @param icType the used information checking algorithm
     */
    public void setInformationChecking(ICType icType) {
        this.informationChecking = icType;
    }

    /**
     * @return the share's X-value (same as id)
     */
    public int getX() {
        return id;
    }

    /**
     * @return the share's id (same as x-value)
     */
    public byte getId() {
        return id;
    }

    /**
     * @return the share's main body (y-values)
     */
    @SuppressFBWarnings("EI_EXPOSE_REP")
    public byte[] getYValues() {
        return yValues;
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

    /**
     * This returns a serialized form of the content (plus IC info) of the share.
     *
     * @return the share's byte[] representation containing all information
     * @throws IOException
     */
    public byte[] getSerializedData() throws IOException {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final DataOutputStream sout = new DataOutputStream(out);

        /* serialize main data */
        sout.write(yValues);

        if (informationChecking != ICType.NONE) {
            /* serialize macs */
            writeMap(sout, macs);

            /* serialize keys */
            writeMap(sout, macKeys);
        }

        return out.toByteArray();
    }

    /**
     * This returns a Map of the metadata that are common to all share types;
     * the idea is that the getMetaData()-implementations in all the share types
     * first get this Map and then add their own special keys
     *
     * @return the metadata that are common to all shares
     */
    HashMap<String, String> getCommonMetaData() {
        HashMap<String, String> res = new HashMap<>();
        res.put("archistar-share-type", getShareType());
        res.put("archistar-version", Integer.toString(VERSION));
        res.put("archistar-id", Byte.toString(id));
        res.put("archistar-ic-type", Integer.toString(informationChecking.ordinal()));
        res.put("archistar-length", Integer.toString(yValues.length));
        return res;
    }

    /**
     * @return the (internal) metadata of a share necessary for reconstruction
     */
    public abstract HashMap<String, String> getMetaData();

    /**
     * @return macs used during secret checking (TODO: add sane interface)
     */
    public Map<Byte, byte[]> getMacs() {
        return this.macs;
    }

    /**
     * @return keys used during secret checking (TODO: add sane interface)
     */
    public Map<Byte, byte[]> getMacKeys() {
        return this.macKeys;
    }

    /**
     * a (too) simple method for validation
     *
     * @return is this share valid?
     */
    public boolean isValid() {
        return !(id <= 0 || yValues == null) && checkICType();
    }

    private boolean checkICType() {

        boolean result = true;

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

    /**
     * compare two shares
     *
     * @param t the share to be compared
     * @return +/-1 if different, 0 if same
     */
    @Override
    public int compareTo(Share t) {

        try {
            if (Arrays.equals(getSerializedData(), t.getSerializedData())) {
                return 0;
            } else {
                return t.id - id;
            }
        } catch (IOException ex) {
            return t.id - id;
        }
    }

    /**
     * compare two shares
     *
     * @param o the other share
     * @return true if the same
     */
    @Override
    public boolean equals(Object o) {
        if (o instanceof Share) {
            return ((Share) o).compareTo(this) == 0;
        } else {
            return false;
        }
    }

    /**
     * (not implemented yet)
     *
     * @return an unique hash for the share
     */
    @Override
    public int hashCode() {
        assert false : "hashCode not implemented";
        return 42;
    }

    /**
     * @return a String representation of the type of the share
     */
    public abstract String getShareType();

    /**
     * @return the length of the original file
     */
    public abstract int getOriginalLength();
}
