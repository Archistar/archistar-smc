package at.archistar.crypto.data;

import java.util.HashMap;
import java.util.Map;

/**
 * @author florian
 */
public class RabinShare extends Share {

    private int originalLength;

    /**
     * a Rabin share with Information Checking
     */
    public RabinShare(byte id, byte[] body, Share.ICType ic,
                      Map<Byte, byte[]> macKeys, Map<Byte, byte[]> macs, int originalLength) throws InvalidParametersException {
        super(id, body, ic, macKeys, macs);
        if (originalLength <= body.length) {
            throw new InvalidParametersException("the given original length cannot be right");
        }
        this.originalLength = originalLength;
    }

    /**
     * a Rabin share without Information Checking
     */
    public RabinShare(byte id, byte[] body, int originalLength) throws InvalidParametersException {
        super(id, body);
        if (originalLength <= body.length) {
            throw new InvalidParametersException("the given original length cannot be right");
        }
        this.originalLength = originalLength;
    }

    @Override
    public HashMap<String, String> getMetaData() {
        HashMap<String, String> res = super.getCommonMetaData();
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
}
