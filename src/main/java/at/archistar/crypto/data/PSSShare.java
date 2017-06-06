package at.archistar.crypto.data;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import static at.archistar.crypto.data.InformationCheckingShare.ICType.RABIN_BEN_OR;

/**
 * @author florian
 */
public class PSSShare extends ShamirShare implements InformationCheckingShare {

    /** keys used during information checking */
    private final Map<Byte, byte[]> macKeys;
    /** macs generated during information checking */
    private final Map<Byte, byte[]> macs;

    private final ICType ICType;

    /**
     * A PSS Share (Shamir + Rabin-Ben-Or Information Checking)
     */
    public PSSShare(byte id, byte[] body, Map<Byte, byte[]> macKeys, Map<Byte, byte[]> macs) throws InvalidParametersException {
        super(id, body);
        this.macKeys = macKeys;
        this.macs = macs;
        this.ICType = RABIN_BEN_OR;
    }

    @Override
    public HashMap<String, String> getMetaData() {
        HashMap<String, String> res = super.getCommonMetaData();
        res.put("archistar-ic-type", Integer.toString(ICType.ordinal()));
        return res;
    }

    @Override
    public String getShareType() {
        return "PSS";
    }

    @Override
    public byte[] getSerializedData() throws IOException {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final DataOutputStream sout = new DataOutputStream(out);

            /* serialize main data */
        sout.write(body);

            /* serialize macs */
        Share.writeMap(sout, macs);

            /* serialize keys */
        Share.writeMap(sout, macKeys);

        return out.toByteArray();
    }

    @Override
    public Map<Byte, byte[]> getMacs() {
        return macs;
    }

    @Override
    public Map<Byte, byte[]> getMacKeys() {
        return macKeys;
    }

    @Override
    public InformationCheckingShare.ICType getICType() {
        return ICType;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        PSSShare pssShare = (PSSShare) o;
        return ICType == pssShare.ICType;
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), macKeys, macs, ICType);
    }
}
