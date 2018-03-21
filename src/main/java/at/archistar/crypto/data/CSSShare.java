package at.archistar.crypto.data;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Map;
import java.util.Objects;

/**
 * @author florian
 */
public class CSSShare extends KrawczykShare {

    /** sha-256 hashes of all shares */
    private final Map<Byte, byte[]> fingerprints;

    /**
     * A CSS Share (Krawczyk with fingerprinting)
     */
    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public CSSShare(byte id, byte[] body, Map<Byte, byte[]> fingerprints, int originalLength, int encAlgorithm, byte[] encKey) throws InvalidParametersException {
        super(id, body, originalLength, encAlgorithm, encKey);
        this.fingerprints = fingerprints;
    }

    public CSSShare(KrawczykShare source, Map<Byte, byte[]> fingerprints) throws InvalidParametersException {
        super(source.getId(), source.getYValues(), source.getOriginalLength(), source.getEncAlgorithm(), source.getKey());
        this.fingerprints = fingerprints;
    }

    public Map<Byte, byte[]> getFingerprints() {
        return this.fingerprints;
    }

    @Override
    @SuppressFBWarnings("EI_EXPOSE_REP")
    public byte[] getSerializedData() throws IOException {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final DataOutputStream sout = new DataOutputStream(out);

            /* serialize main data */
        sout.write(body);

            /* serialize fingerprints */
        Share.writeMap(sout, fingerprints);

        return out.toByteArray();
    }

    @Override
    public String getShareType() {
        return "CSS";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        CSSShare cssShare = (CSSShare) o;
        return Objects.equals(fingerprints, cssShare.fingerprints);
    }

    @Override
    public String toString() {
        return "CSSShare{" +
                "x=" + getId() +
                ", body.length=" + body.length +
                ", originalLength=" + getOriginalLength() +
                ", encAlgorithm=" + getEncAlgorithm() +
                '}';
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), fingerprints);
    }
}
