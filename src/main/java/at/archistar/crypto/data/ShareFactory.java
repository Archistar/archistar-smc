package at.archistar.crypto.data;

import at.archistar.crypto.data.Share.ShareType;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * This helper class is used to instantiate or deserialize shares
 */
public class ShareFactory {
 
    /**
     * Deserialize a single share out of the input byte array.
     * 
     * Note: this method does *not* employ (possible) information checking data
     *       when determining if the share is valid
     * 
     * @param byteInput the serialized share
     * @return the deserialized share
     * @throws InvalidParametersException if the input did not contain a valid
     *                                    share
     */
    public static Share deserialize(byte[] byteInput) throws InvalidParametersException {
        if (byteInput == null) {
            throw new InvalidParametersException("how should you deserialize from null?");
        }
        
        ByteArrayInputStream bis = new ByteArrayInputStream(byteInput);
        DataInputStream is = new DataInputStream(bis);
        
        return ShareFactory.deserialize(is);
    }
    
    /**
     * Deserialize a single share out of the input stream.
     * 
     * Note: this method does *not* employ (possible) information checking data
     *       when determining if the share is valid
     * 
     * @param is the serialized share
     * @return the deserialized share
     * @throws InvalidParametersException if the input did not contain a valid
     *                                    share
     */
    public static Share deserialize(DataInputStream is) throws InvalidParametersException {
        if (is == null) {
            throw new InvalidParametersException("how should you deserialize from null?");
        }

        try {
            /* version */
            int version = is.readInt();
            if (version != Share.VERSION) {
                throw new InvalidParametersException("Different on-disk format verson");
            }

            /* algorithm */
            ShareType alg = readShareType(is);
            
            /* information checking type */
            Share.ICType ic = readICType(is);

            /* id */
            byte id = is.readByte();

            /* metadata */
            Map<Byte, byte[]> metadata = readMap(is);

            /* body */
            int tmpLength = is.readInt();
            byte body[] = new byte[tmpLength];
            is.readFully(body);

            Map<Byte, byte[]> macs;
            Map<Byte, byte[]> macKeys;
            if (ic != Share.ICType.NONE) {
                macs = readMap(is);
                macKeys = readMap(is);
            } else {
                macs = new HashMap<>();
                macKeys = new HashMap<>();
            }

            /* create share */
            Share result = create(alg, id, body, metadata, ic, macKeys, macs);

            // check for EOF
            checkForEOF(is);
            
            return result;
        } catch (IOException ex) {
            throw new InvalidParametersException("error during deserialization: " + ex.getLocalizedMessage());
        }
    }
    
    private static void checkForEOF(DataInputStream is) throws InvalidParametersException, IOException {
        try {
            is.readByte();
            throw new InvalidParametersException("data was too long");
        } catch (EOFException ex) {
        }
    }
    
    /**
     * create a new share from given data (without information checking data)
     * 
     * @param algorithm the share type
     * @param id the share's id (i.e. x value)
     * @param yValues the share's body (i.e. y values)
     * @param metadata attached metadata
     * @return the newly created share
     */
    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public static Share create(ShareType algorithm, byte id, byte[] yValues, Map<Byte, byte[]> metadata) throws InvalidParametersException {
        return create(algorithm, id, yValues, metadata,
                      Share.ICType.NONE,
                      new HashMap<Byte, byte[]>(),
                      new HashMap<Byte, byte[]>());
    }

    /**
     * create a new share from given data with information checking data
     * 
     * @param algorithm the share type
     * @param id the share's id (i.e. x value)
     * @param yValues the share's body (i.e. y values)
     * @param metadata attached metadata
     * @param ic the information checking scheme that was used
     * @param macs the macs which were generated during information checking
     * @param macKeys the keys used during information checking
     * @return the newly created share
     */
    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public static Share create(ShareType algorithm, byte id, byte[] yValues,
                               Map<Byte, byte[]> metadata,
                               Share.ICType ic, Map<Byte, byte[]> macKeys, Map<Byte, byte[]> macs) throws InvalidParametersException {
        
        Share share = new Share(algorithm, id, yValues, metadata,
                                ic, macKeys, macs);
        
        if (share.isValid()) {
            return share;
        } else {
            throw new InvalidParametersException("not a valid share");
        }
    }
    
    private static Map<Byte, byte[]> readMap(DataInputStream is) throws IOException {
        int tmp = is.readInt();
        Map<Byte, byte[]> macs = new HashMap<>();
        for (int i = 0; i < tmp; i++) {
            byte tmpId = is.readByte();
            int length = is.readInt();
            byte[] data = new byte[length];
            is.readFully(data);
            macs.put(tmpId, data);
        }
        return macs;
    }

    private static Share.ICType readICType(DataInputStream is) throws InvalidParametersException, IOException {
            byte algByte = is.readByte();
            
            if (algByte >= 0 && algByte < Share.ICType.values().length) {
                return Share.ICType.values()[algByte];
            } else {
                throw new InvalidParametersException("unknown share type");
            }
    }

    private static ShareType readShareType(DataInputStream is) throws IOException, InvalidParametersException {
        byte algByte = is.readByte();
        if (algByte >= 0 && algByte < ShareType.values().length) {
            return ShareType.values()[algByte];
        } else {
            throw new InvalidParametersException("unknown share type");
        }
    }
}
