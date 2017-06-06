package at.archistar.crypto.data;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import static org.fest.assertions.api.Assertions.fail;

/**
 * Perform serialization tests upon Shares that contain information-checking
 * information.
 *
 * NOTE: currently the content of the stored keys/macs is not checked by
 * the serialization algorithm but has to be done manually by the
 * information checking implementation
 */
public class TestShareWithICSerialization extends AbstractSerializationTest {
    @Before
    public void setupData() throws InvalidParametersException, IOException {
        Map<Byte, byte[]> macs = new HashMap<>();
        macs.put((byte) 1, new byte[]{1, 2, 3});
        macs.put((byte) 2, new byte[]{4, 5, 6});

        Map<Byte, byte[]> macKeys = new HashMap<>();
        macKeys.put((byte) 1, new byte[]{7, 8, 9});
        macKeys.put((byte) 2, new byte[]{10, 11, 12});

        share = new PSSShare((byte) 7, new byte[]{1,2,3}, macKeys, macs);
        metaData = share.getMetaData();
        serializedShare = share.getSerializedData();
    }

    /**
     * with IC, partial shares should throw an exception
     *
     * @throws at.archistar.crypto.data.InvalidParametersException this should be thrown
     * @throws java.io.IOException this shouldn't be thrown
     */
    @Override
    @Test(expected = InvalidParametersException.class)
    public void failingWithPartialShares() throws IOException, InvalidParametersException {
        byte[] tmp = Arrays.copyOf(serializedShare, serializedShare.length - 1);
        Share s = ShareFactory.deserialize(tmp, metaData);
        fail("there was not enough data for this type of share");
    }
}
