package at.archistar.crypto.data;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Objects;

/**
 * @author florian
 */
public class ShamirShare implements Share {

    private final byte id;
    final byte[] body;

    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public ShamirShare(byte id, byte[] body) throws InvalidParametersException {
        if (id == 0) {
            throw new InvalidParametersException("X must not be 0");
        }
        this.id = id;
        this.body = body;
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
        return getCommonMetaData();
    }

    @Override
    public String getShareType() {
        return "SHAMIR";
    }

    @Override
    public int getOriginalLength() {
        return body.length;
    }

    @Override
    public String toString() {
        return "ShamirShare{" +
                "x=" + id +
                ", body.length=" + body.length +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ShamirShare that = (ShamirShare) o;
        return id == that.id &&
                Arrays.equals(body, that.body);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, body);
    }
}
