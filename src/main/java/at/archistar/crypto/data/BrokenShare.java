package at.archistar.crypto.data;

import java.io.IOException;
import java.util.HashMap;

/**
 * @author florian
 */
public class BrokenShare implements Share {

    private final String error;

    BrokenShare(String error) {
        this.error = error;
    }

    public String getError() {
        return error;
    }

    @Override
    public int getX() {
        return 0;
    }

    @Override
    public byte getId() {
        return 0;
    }

    @Override
    public byte[] getYValues() {
        return new byte[0];
    }

    @Override
    public byte[] getSerializedData() throws IOException {
        return new byte[0];
    }

    @Override
    public HashMap<String, String> getMetaData() {
        return getCommonMetaData();
    }

    @Override
    public String getShareType() {
        return "BROKEN";
    }

    @Override
    public int getOriginalLength() {
        return 0;
    }
}
