package at.archistar.crypto.data;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Represent a Share in memory (including metadata and information checking
 * information). Shares are always created by the ShareFactory helper class.
 */
public interface Share extends Comparable<Share> {

    /** on-disk version of the share */
    int VERSION = 5;

    static void writeMap(DataOutputStream sout, Map<Byte, byte[]> map) throws IOException {
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
     * @return the share's X-value (same as id)
     */
    int getX();

    /**
     * @return the share's id (same as x-value)
     */
    byte getId();

    /**
     * @return the share's main body (y-values)
     */
    @SuppressFBWarnings("EI_EXPOSE_REP")
    byte[] getYValues();

    /**
     * This returns a serialized form of the content (plus IC info) of the share.
     *
     * @return the share's byte[] representation containing all information
     * @throws IOException
     */
    byte[] getSerializedData() throws IOException;

    /**
     * This returns a Map of the metadata that are common to all share types;
     * the idea is that the getMetaData()-implementations in all the share types
     * first get this Map and then add their own special keys
     *
     * @return the metadata that are common to all shares
     */
    default HashMap<String, String> getCommonMetaData() {
        HashMap<String, String> res = new HashMap<>();
        res.put("archistar-share-type", getShareType());
        res.put("archistar-version", Integer.toString(VERSION));
        res.put("archistar-id", Byte.toString(getId()));
        res.put("archistar-length", Integer.toString(getYValues().length));
        return res;
    }

    /**
     * @return the (internal) metadata of a share necessary for reconstruction
     */
    HashMap<String, String> getMetaData();

    /**
     * compare two shares
     *
     * @param t the share to be compared
     * @return +/-1 if different, 0 if same
     */
    @Override
    default int compareTo(Share t) {

        try {
            if (Arrays.equals(getSerializedData(), t.getSerializedData())) {
                return 0;
            } else {
                return t.getId()- getId();
            }
        } catch (IOException ex) {
            return t.getId() - getId();
        }
    }

    /**
     * @return a String representation of the type of the share
     */
    String getShareType();

    /**
     * @return the length of the original file
     */
    int getOriginalLength();
}
