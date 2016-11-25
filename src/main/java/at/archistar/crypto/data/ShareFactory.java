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
     *
     * Note: this method does *not* employ (possible) information checking data
     * when determining if the share is valid
     *
     * @param data the raw shared data (plus IC data at the end)
     * @param metaData the additional data needed to reconstruct the share
     * @return the deserialized share
     * @throws InvalidParametersException if the input did not contain a valid share
     */
    @SuppressWarnings("cyclomaticcomplexity")
    public static Share deserialize(byte[] data, Map<String, String> metaData) throws InvalidParametersException {

        if (data == null || data.length == 0) {
            throw new InvalidParametersException("No data received");
        }

        final String version = metaData.get("archistar-version");
        if (version == null) {
            throw new InvalidParametersException("Invalid share. No \"version\" datum found");
        }
        if (!version.equalsIgnoreCase(Integer.toString(Share.VERSION))) {
            throw new InvalidParametersException("This share is of version " + version +
                    ", but version " + Share.VERSION + " was expected");
        }

        /* information checking type */
        final String icS = metaData.get("archistar-ic-type");
        if (icS == null) {
            throw new InvalidParametersException("Invalid share. No \"ic-type\" datum found");
        }
        final Share.ICType ic = parseICType(icS);

        /* id == x-value of the share */
        final String idS = metaData.get("archistar-id");
        if (idS == null) {
            throw new InvalidParametersException("Invalid share. No \"id\" datum found");
        }
        final byte id = Byte.parseByte(idS);

        /* length of the data part of the share (rest is IC metadata) */
        final String lenS = metaData.get("archistar-length");
        if (lenS == null) {
            throw new InvalidParametersException("Invalid share. No \"length\" datum found");
        }
        final int length = Integer.parseInt(lenS);

        if (data.length > length && ic == Share.ICType.NONE) {
            throw new InvalidParametersException("Invalid share. Data too long");
        }

        try {

            byte body[];
            Map<Byte, byte[]> macs;
            Map<Byte, byte[]> macKeys;

            if (data.length <= length || ic == Share.ICType.NONE) {
                // if data.length <= length, this must be a partial share
                // so: no IC info either
                body = data;
                macs = new HashMap<>();
                macKeys = new HashMap<>();
            } else {
                // a full share with IC info
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

            /* algorithm */
            final String sT = metaData.get("archistar-share-type");
            if (sT == null) {
                throw new InvalidParametersException("Invalid share. No \"share-type\" datum found");
            }

            switch (sT) {
                case "SHAMIR":
                    return new ShamirShare(id, body, ic, macKeys, macs);

                case "RABIN":
                    final String olrS = metaData.get("archistar-original-length");
                    if (olrS == null) {
                        throw new InvalidParametersException("Invalid Rabin share. No \"original-length\" datum found");
                    }
                    final int originalLengthRabin = Integer.parseInt(olrS);

                    return new RabinShare(id, body, ic, macKeys, macs, originalLengthRabin);

                case "KRAWCZYK":
                    final String olkS = metaData.get("archistar-original-length");
                    if (olkS == null) {
                        throw new InvalidParametersException("Invalid Krawczyk share. No \"original-length\" datum found");
                    }
                    final int originalLengthKrawczyk = Integer.parseInt(olkS);

                    final String encAlgoS = metaData.get("archistar-krawczyk-algorithm");
                    if (encAlgoS == null) {
                        throw new InvalidParametersException("Invalid Krawczyk share. No \"krawczyk-algorithm\" datum found");
                    }
                    int encAlgorithm = Integer.parseInt(encAlgoS);

                    final String encKeyS = metaData.get("archistar-krawczyk-key");
                    if (encKeyS == null) {
                        throw new InvalidParametersException("Invalid Krawczyk share. No \"krawczyk-key\" datum found");
                    }
                    final byte[] encKey = Base64.decode(encKeyS);

                    return new KrawczykShare(id, body, ic, macKeys, macs, originalLengthKrawczyk, encAlgorithm, encKey);

                case "NTT_SHAMIR":
                    final String olnsS = metaData.get("archistar-original-length");
                    if (olnsS == null) {
                        throw new InvalidParametersException("Invalid NTT Shamir share. No \"original-length\" datum found");
                    }
                    final int originalLengthNTTShamir = Integer.parseInt(olnsS);

                    final String nsS = metaData.get("archistar-ntt-share-size");
                    if (nsS == null) {
                        throw new InvalidParametersException("Invalid NTT Shamir share. No \"ntt-share-size\" datum found");
                    }
                    final int nttShamirShareSize = Integer.parseInt(nsS);
                    return new NTTShamirShare(id, body, ic, macKeys, macs, originalLengthNTTShamir, nttShamirShareSize);

                case "NTT_RABIN":
                    final String olnrS = metaData.get("archistar-original-length");
                    if (olnrS == null) {
                        throw new InvalidParametersException("Invalid NTT Rabin share. No \"original-length\" datum found");
                    }
                    final int originalLengthNTTRabin = Integer.parseInt(olnrS);

                    final String nrS = metaData.get("archistar-ntt-share-size");
                    if (nrS == null) {
                        throw new InvalidParametersException("Invalid NTT Rabin share. No \"ntt-share-size\" datum found");
                    }
                    final int nttRabinShareSize = Integer.parseInt(nrS);
                    return new NTTRabinShare(id, body, ic, macKeys, macs, originalLengthNTTRabin, nttRabinShareSize);

                default:
                    throw new InvalidParametersException("Unknown share type: " + sT);
            }
        } catch (IOException ex) {
            throw new InvalidParametersException("error during deserialization: " + ex.getLocalizedMessage());
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

    private static Share.ICType parseICType(String s) throws InvalidParametersException {
        int idx = Integer.parseInt(s);
        if (idx >= 0 && idx < Share.ICType.values().length) {
            return Share.ICType.values()[idx];
        } else {
            throw new InvalidParametersException("unknown share type");
        }
    }
}
