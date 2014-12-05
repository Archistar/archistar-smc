package at.archistar.crypto.data;

import static at.archistar.crypto.data.Share.ORIGINAL_LENGTH;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;
import org.junit.Before;

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
        Map<Byte, byte[]> metadata = new HashMap<>();
        metadata.put(ORIGINAL_LENGTH, ByteBuffer.allocate(4).putInt(1).array());
        
        Map<Byte, byte[]> macs = new HashMap<>();
        macs.put((byte) 1, new byte[]{1, 2, 3});
        macs.put((byte) 2, new byte[]{4, 5, 6});

        Map<Byte, byte[]> macKeys = new HashMap<>();
        macKeys.put((byte) 1, new byte[]{7, 8, 9});
        macKeys.put((byte) 2, new byte[]{10, 11, 12});

        
        share = ShareFactory.create(Share.ShareType.REED_SOLOMON, (byte)7,
                                    new byte[]{1,2,3}, metadata,
                                    Share.ICType.RABIN_BEN_OR, macKeys, macs);
        
        serializedShare = share.serialize();
    }
}
