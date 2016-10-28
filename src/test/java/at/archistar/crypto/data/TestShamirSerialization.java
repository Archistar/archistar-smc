package at.archistar.crypto.data;

import static at.archistar.crypto.data.Share.ORIGINAL_LENGTH;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;

/**
 * Perform serialization tests upon Shamir shares
 */
public class TestShamirSerialization extends AbstractSerializationTest {
    @Before
    public void setupData() throws InvalidParametersException, IOException {
        Map<Byte, byte[]> metadata = new HashMap<>();
        metadata.put(ORIGINAL_LENGTH, ByteBuffer.allocate(4).putInt(3).array());

        share = ShareFactory.create(Share.ShareType.SHAMIR_PSS, (byte) 7,
                new byte[]{1, 2, 3}, metadata);

        serializedShare = share.serialize();
    }
}
