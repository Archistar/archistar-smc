package at.archistar.crypto.data;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Objects;

/**
 * @author florian
 */
public class RabinShare implements Share {

    private byte id;
    private byte[] body;
    private int originalLength;

    /**
     * A Rabin share
     */
    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public RabinShare(byte id, byte[] body, int originalLength) throws InvalidParametersException {
        if (id == 0) {
            throw new InvalidParametersException("X must not be 0");
        }
        this.id = id;
        this.body = body;
        this.originalLength = originalLength;
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
        return res;
    }

    @Override
    public String getShareType() {
        return "RABIN";
    }

    @Override
    public int getOriginalLength() {
        return this.originalLength;
    }

    @Override
    public String toString() {
        return "RabinShare{" +
                "x=" + id +
                ", body.length=" + body.length +
                ", originalLength=" + originalLength +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RabinShare that = (RabinShare) o;
        return id == that.id &&
                originalLength == that.originalLength &&
                Arrays.equals(body, that.body);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, body, originalLength);
    }
}
