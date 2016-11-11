package at.archistar.crypto.data;

import java.util.HashMap;
import java.util.Map;

/**
 * @author florian
 */
public class ShamirShare extends Share {

    /**
     * a Shamir share with Information Checking
     */
    public ShamirShare(byte id, byte[] body, ICType ic,
                       Map<Byte, byte[]> macKeys, Map<Byte, byte[]> macs) throws InvalidParametersException {
        super(id, body, ic, macKeys, macs);
    }

    /**
     * a Shamir share without Information Checking
     */
    public ShamirShare(byte id, byte[] body) throws InvalidParametersException {
        super(id, body);
    }

    @Override
    public HashMap<String, String> getMetaData() {
        return super.getCommonMetaData();
    }

    @Override
    public String getShareType() {
        return "SHAMIR";
    }

    @Override
    public int getOriginalLength() {
        return getYValues().length;
    }
}
