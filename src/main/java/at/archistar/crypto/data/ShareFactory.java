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
 *
 * @author andy
 */
public class ShareFactory {
    
    public static Share deserialize(byte[] byteInput) throws InvalidParametersException {
        if (byteInput == null) {
            throw new InvalidParametersException("how should you deserialize from null?");
        }
        
        ByteArrayInputStream bis = new ByteArrayInputStream(byteInput);
        DataInputStream is = new DataInputStream(bis);
        
        return ShareFactory.deserialize(is);
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
            ShareType alg = null;
            byte algByte = is.readByte();
            if (algByte >= 0 && algByte < ShareType.values().length) {
                alg = ShareType.values()[algByte];
            } else {
                throw new InvalidParametersException("unknown share type");
            }
            
            Share.ICType ic = null;
            algByte = is.readByte();
            if (algByte >= 0 && algByte < Share.ICType.values().length) {
                ic = Share.ICType.values()[algByte];
            } else {
                throw new InvalidParametersException("unknown share type");
            }

            /* id */
            byte id = is.readByte();

            /* metadata */
            Map<Byte, Integer> metadata = new HashMap<>();
            int tmp = is.readInt();
            for (int i = 0; i < tmp; i++) {
                byte mdId = is.readByte();
                int mdValue = is.readInt();
                metadata.put(mdId, mdValue);
            }

            /* body */
            byte[] body;
            byte[] key = null;

            int tmpLength = is.readInt();
            if (alg == ShareType.KRAWCZYK) {
                int yLength = is.readInt();
                int keyLength = is.readInt();

                body = new byte[yLength];
                key = new byte[keyLength];

                is.readFully(body);
                is.readFully(key);
            } else {
                body = new byte[tmpLength];
                is.readFully(body);
            }

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
            Share result;
            if (alg != ShareType.KRAWCZYK) {
                result = new Share(alg, id, body, metadata, ic, macKeys, macs);
            } else {
                result = new KrawczykShare(id, body, key, metadata, ic, macKeys, macs);
            }

            // check for EOF
            try {
                is.readByte();
                throw new InvalidParametersException("data was too long");
            } catch (EOFException ex) {
                return result;
            }

        } catch (IOException ex) {
            throw new InvalidParametersException("error during deserialization: " + ex.getLocalizedMessage());
        }
    }
    
    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public static Share create(ShareType algorithm, byte id, byte[] yValues, Map<Byte, Integer> metadata) throws InvalidParametersException {
        Share share = new Share(algorithm, id, yValues, metadata);
        
        if (share.isValid()) {
            return share;
        } else {
            throw new InvalidParametersException("not a valid share");
        }

    }
    
    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public static Share create(ShareType algorithm, byte id, byte[] yValues,
                               Map<Byte, Integer> metadata,
                               Share.ICType ic, Map<Byte, byte[]> macKeys, Map<Byte, byte[]> macs) throws InvalidParametersException {
        
        Share share = new Share(algorithm, id, yValues, metadata,
                                ic, macKeys, macs);
        
        if (share.isValid()) {
            return share;
        } else {
            throw new InvalidParametersException("not a valid share");
        }
    }

    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public static Share createKrawczyk(byte id, byte[] key, byte[] yVals, Map<Byte, Integer> metadata) throws InvalidParametersException {
        Share share = new KrawczykShare(id, key, yVals, metadata);
        
        if (share.isValid()) {
            return share;
        } else {
            throw new InvalidParametersException("not a valid share");
        }
    }
    
    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public static Share createKrawczyk(byte id, byte[] key, byte[] yVals,
                                       Map<Byte, Integer> metadata, Map<Byte, byte[]> macKeys,
                                       Share.ICType ic, Map<Byte, byte[]> macs) throws InvalidParametersException {
        
        Share share = new KrawczykShare(id, key, yVals, metadata, ic, macKeys, macs);
        
        if (share.isValid()) {
            return share;
        } else {
            throw new InvalidParametersException("not a valid share");
        }
    }
}
