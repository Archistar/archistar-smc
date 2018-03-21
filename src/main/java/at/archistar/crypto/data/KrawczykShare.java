package at.archistar.crypto.data;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.bouncycastle.util.encoders.Base64;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Objects;

/**
 * @author florian
 */
public class KrawczykShare implements Share {

    private final byte id;

    final byte[] body;

    /** length of the original file */
    private final int originalLength;

    /** encryption algorithm used */
    private final int encAlgorithm;

    /** key used for the encryption step */
    private final byte[] encKey;

    /**
     * A Raw Krawczyk Share
     */
    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public KrawczykShare(byte id, byte[] body, int originalLength, int encAlgorithm, byte[] encKey) throws InvalidParametersException {
        if (id == 0) {
            throw new InvalidParametersException("X must not be 0");
        }
        this.id = id;
        this.body = body;
        if (encKey == null || encKey.length != 32) {
            throw new InvalidParametersException("invalid key");
        }
        if (encAlgorithm <= 0) {
            throw new InvalidParametersException("invalid algorithm");
        }
        this.originalLength = originalLength;
        this.encAlgorithm = encAlgorithm;
        this.encKey = encKey;
    }

    @Override
    public int getX() {
        return id;
    }

    @Override
    public byte getId() {
        return id;
    }

    @Override
    @SuppressFBWarnings("EI_EXPOSE_REP")
    public byte[] getYValues() {
        return body;
    }

    @Override
    @SuppressFBWarnings("EI_EXPOSE_REP")
    public byte[] getSerializedData() throws IOException {
        return body;
    }

    @Override
    public HashMap<String, String> getMetaData() {
        HashMap<String, String> res = getCommonMetaData();
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
        return originalLength;
    }

    public int getEncAlgorithm() {
        return encAlgorithm;
    }

    /**
     * @return the key used to encrypt the data
     */
    @SuppressFBWarnings("EI_EXPOSE_REP")
    public byte[] getKey() {
        return encKey;
    }

    @Override
    public String toString() {
        return "KrawczykShare{" +
                "x=" + id +
                ", body.length=" + body.length +
                ", originalLength=" + originalLength +
                ", encAlgorithm=" + encAlgorithm +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KrawczykShare that = (KrawczykShare) o;
        return id == that.id &&
                originalLength == that.originalLength &&
                encAlgorithm == that.encAlgorithm &&
                Arrays.equals(body, that.body) &&
                Arrays.equals(encKey, that.encKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, body, originalLength, encAlgorithm, encKey);
    }
}
