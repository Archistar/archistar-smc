package at.archistar.crypto.data;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.bouncycastle.util.encoders.Base64;

import java.util.HashMap;
import java.util.Map;

/**
 * @author florian
 */
public class KrawczykShare extends Share {

    private final int originalLength;

    private final int encAlgorithm;

    private final byte[] encKey;

    /**
     * a Krawczyk share with Information Checking
     */
    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public KrawczykShare(byte id, byte[] body, ICType ic, Map<Byte, byte[]> macKeys, Map<Byte, byte[]> macs,
                         int originalLength, int encAlgorithm, byte[] encKey) throws InvalidParametersException {
        super(id, body, ic, macKeys, macs);
        if (encKey == null || encKey.length != 32) {
            throw new InvalidParametersException("invalid key");
        }
        if (encAlgorithm <= 0 || encAlgorithm >= ICType.values().length) {
            throw new InvalidParametersException("invalid algorithm");
        }
        this.originalLength = originalLength;
        this.encAlgorithm = encAlgorithm;
        this.encKey = encKey;
    }

    /**
     * a Krawczyk share without Information Checking
     */
    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public KrawczykShare(byte id, byte[] body, int originalLength, int encAlgorithm, byte[] encKey) throws InvalidParametersException {
        super(id, body);
        if (encKey == null || encKey.length != 32) {
            throw new InvalidParametersException("invalid key");
        }
        if (encAlgorithm <= 0 || encAlgorithm >= ICType.values().length) {
            throw new InvalidParametersException("invalid algorithm");
        }
        this.originalLength = originalLength;
        this.encAlgorithm = encAlgorithm;
        this.encKey = encKey;
    }

    @Override
    public HashMap<String, String> getMetaData() {
        HashMap<String, String> res = super.getCommonMetaData();
        res.put("archistar-original-length", Integer.toString(originalLength));
        res.put("archistar-krawczyk-algorithm", Integer.toString(encAlgorithm));
        res.put("archistar-krawczyk-key", Base64.toBase64String(encKey));
        return res;
    }

    @Override
    public String getShareType() {
        return "KRAWCZYK";
    }

    @Override
    public int getOriginalLength() {
        return this.originalLength;
    }

    /**
     * @return the key used to encrypt the data
     */
    @SuppressFBWarnings("EI_EXPOSE_REP")
    public byte[] getKey() {
        return this.encKey;
    }
}
