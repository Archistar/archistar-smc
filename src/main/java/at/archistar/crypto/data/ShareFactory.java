package at.archistar.crypto.data;

import org.bouncycastle.util.encoders.Base64;

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
     * Deserialize a single share out of the raw shared data plus metadata.
     * On error, a BrokenShare is returned
     *
     * Note: this method does *not* employ (possible) information checking data
     * when determining if the share is valid
     *
     * @param data the raw shared data (plus IC data at the end)
     * @param metaData the additional data needed to reconstruct the share
     * @return the deserialized share
     */
    @SuppressWarnings("cyclomaticcomplexity")
    public static Share deserialize(byte[] data, Map<String, String> metaData) {

        if (data == null) {
            return new BrokenShare("No data received");
        }

        final String version = metaData.get("archistar-version");
        if (version == null) {
            return new BrokenShare("Invalid share. No \"version\" datum found");
        }
        if (!version.equalsIgnoreCase(Integer.toString(Share.VERSION))) {
            return new BrokenShare("This share is of version " + version +
                    ", but version " + Share.VERSION + " was expected");
        }

        /* id == x-value of the share */
        final String idS = metaData.get("archistar-id");
        if (idS == null) {
            return new BrokenShare("Invalid share. No \"id\" datum found");
        }
        final byte id = Byte.parseByte(idS);

        /* length of the data part of the share (rest is IC metadata) */
        final String lenS = metaData.get("archistar-length");
        if (lenS == null) {
            return new BrokenShare("Invalid share. No \"length\" datum found");
        }
        final int length = Integer.parseInt(lenS);

        try {

            /* algorithm */
            final String sT = metaData.get("archistar-share-type");
            if (sT == null) {
                return new BrokenShare("Invalid share. No \"share-type\" datum found");
            }

            switch (sT) {
                case "SHAMIR":
                    if (data.length > length) {
                        return new BrokenShare("Received more data than expected");
                    }
                    return new ShamirShare(id, data);

                case "RABIN":
                    if (data.length > length) {
                        return new BrokenShare("Received more data than expected");
                    }
                    final String olrS = metaData.get("archistar-original-length");
                    if (olrS == null) {
                        return new BrokenShare("Invalid Rabin share. No \"original-length\" datum found");
                    }
                    final int originalLengthRabin = Integer.parseInt(olrS);

                    return new RabinShare(id, data, originalLengthRabin);

                case "KRAWCZYK":
                    if (data.length > length) {
                        return new BrokenShare("Received more data than expected");
                    }
                    final String olkS = metaData.get("archistar-original-length");
                    if (olkS == null) {
                        return new BrokenShare("Invalid Krawczyk share. No \"original-length\" datum found");
                    }
                    final int originalLengthKrawczyk = Integer.parseInt(olkS);

                    final String encAlgoS = metaData.get("archistar-krawczyk-algorithm");
                    if (encAlgoS == null) {
                        return new BrokenShare("Invalid Krawczyk share. No \"krawczyk-algorithm\" datum found");
                    }
                    int encAlgorithm = Integer.parseInt(encAlgoS);

                    final String encKeyS = metaData.get("archistar-krawczyk-key");
                    if (encKeyS == null) {
                        return new BrokenShare("Invalid Krawczyk share. No \"krawczyk-key\" datum found");
                    }
                    final byte[] encKey = Base64.decode(encKeyS);

                    return new KrawczykShare(id, data, originalLengthKrawczyk, encAlgorithm, encKey);

                case "PSS":
                    /* information checking type */
                    final String icS = metaData.get("archistar-ic-type");
                    if (icS == null) {
                        return new BrokenShare("Invalid share. No \"ic-type\" datum found");
                    } else if (parseICType(icS) != InformationCheckingShare.ICType.RABIN_BEN_OR) {
                        return new BrokenShare("Information checking with PSS must be RABIN_BEN_OR");
                    }

                    byte[] body;

                    Map<Byte, byte[]> macs;
                    Map<Byte, byte[]> macKeys;

                    if (data.length <= length) {
                        // if data.length <= length, this must be a partial share
                        body = data;
                        macs = new HashMap<>();
                        macKeys = new HashMap<>();
                    } else {
                        // a full share
                        body = new byte[length];
                        ByteArrayInputStream bis = new ByteArrayInputStream(data);
                        DataInputStream is = new DataInputStream(bis);
                        is.readFully(body);
                        macs = readMap(is);
                        macKeys = readMap(is);
                        // after reading the mac keys, we should be at the end;
                        // check if we have a full read
                        checkForEOF(is);
                    }

                    return new PSSShare(id, body, macKeys, macs);

                case "CSS":

                    final String olCSS = metaData.get("archistar-original-length");
                    if (olCSS == null) {
                        return new BrokenShare("Invalid Krawczyk share. No \"original-length\" datum found");
                    }
                    final int originalLengthCSS = Integer.parseInt(olCSS);

                    final String encAlgoCSS = metaData.get("archistar-krawczyk-algorithm");
                    if (encAlgoCSS == null) {
                        return new BrokenShare("Invalid Krawczyk share. No \"krawczyk-algorithm\" datum found");
                    }
                    int encAlgorithmCSS = Integer.parseInt(encAlgoCSS);

                    final String encKeyCS = metaData.get("archistar-krawczyk-key");
                    if (encKeyCS == null) {
                        return new BrokenShare("Invalid Krawczyk share. No \"krawczyk-key\" datum found");
                    }
                    final byte[] encKeyCSS = Base64.decode(encKeyCS);

                    Map<Byte, byte[]> fingerprints;

                    if (data.length <= length) {
                        // if data.length <= length, this must be a partial share
                        body = data;
                        fingerprints = new HashMap<>();
                    } else {
                        // a full share
                        body = new byte[length];
                        ByteArrayInputStream bis = new ByteArrayInputStream(data);
                        DataInputStream is = new DataInputStream(bis);
                        is.readFully(body);
                        fingerprints = readMap(is);
                        // after reading the mac keys, we should be at the end;
                        // check if we have a full read
                        checkForEOF(is);
                    }

                    return new CSSShare(id, body, fingerprints, originalLengthCSS, encAlgorithmCSS, encKeyCSS);

                default:
                    return new BrokenShare("Unknown share type: " + sT);
            }
        } catch (IOException | InvalidParametersException ex) {
            return new BrokenShare("error during deserialization: " + ex.getLocalizedMessage());
        }
    }

    private static void checkForEOF(DataInputStream is) throws InvalidParametersException, IOException {
        try {
            is.readByte();
            throw new InvalidParametersException("data was too long");
        } catch (EOFException ignored) {
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

    private static InformationCheckingShare.ICType parseICType(String s) throws InvalidParametersException {
        int idx = Integer.parseInt(s);
        if (idx >= 0 && idx < InformationCheckingShare.ICType.values().length) {
            return InformationCheckingShare.ICType.values()[idx];
        } else {
            throw new InvalidParametersException("unknown share type");
        }
    }
}
