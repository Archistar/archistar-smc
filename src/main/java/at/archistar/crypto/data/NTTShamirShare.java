package at.archistar.crypto.data;

import java.util.HashMap;
import java.util.Map;

/**
 * @author florian
 */
public class NTTShamirShare extends Share {

    private final int originalLength;

    private final int nttShareSize;

    /**
     * a Shamir share using NTT with Information Checking
     */
    public NTTShamirShare(byte id, byte[] body, ICType ic, Map<Byte, byte[]> macKeys, Map<Byte, byte[]> macs,
                          int originalLength, int nttShareSize) throws InvalidParametersException {
        super(id, body, ic, macKeys, macs);
        this.originalLength = originalLength;
        this.nttShareSize = nttShareSize;
    }

    /**
     * a Shamir share using NTT without Information Checking
     */
    public NTTShamirShare(byte id, byte[] body, int originalLength, int nttShareSize) throws InvalidParametersException {
        super(id, body);
        this.originalLength = originalLength;
        this.nttShareSize = nttShareSize;
    }

    @Override
    public HashMap<String, String> getMetaData() {
        HashMap<String, String> res = super.getCommonMetaData();
        res.put("archistar-original-length", Integer.toString(originalLength));
        res.put("archistar-ntt-share-size", Integer.toString(nttShareSize));
        return res;
    }

    @Override
    public String getShareType() {
        return "NTT_SHAMIR";
    }

    @Override
    public int getOriginalLength() {
        return this.originalLength;
    }

    /**
     * @return number of NTT shares used
     */
    public int getNttShareSize() {
        return this.nttShareSize;
    }
}
