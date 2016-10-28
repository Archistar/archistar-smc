package at.archistar.crypto.data;

import static at.archistar.crypto.data.Share.ENC_ALGORITHM;
import static at.archistar.crypto.data.Share.ENC_KEY;
import static at.archistar.crypto.data.Share.ORIGINAL_LENGTH;

import at.archistar.crypto.data.Share.ShareType;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;

/**
 * Perform serialization tests upon Krawcywk shares
 */
public class TestKrawczykSerialization extends AbstractSerializationTest {
    @Before
    public void setupData() throws InvalidParametersException, IOException {
        Map<Byte, byte[]> metadata = new HashMap<>();
        metadata.put(ORIGINAL_LENGTH, ByteBuffer.allocate(4).putInt(1).array());
        metadata.put(ENC_ALGORITHM, ByteBuffer.allocate(4).putInt(1).array());
        metadata.put(ENC_KEY, new byte[]{1, 2, 3});


        share = ShareFactory.create(ShareType.KRAWCZYK, (byte) 7,
                new byte[]{1, 2, 3}, metadata);
        serializedShare = share.serialize();
    }
}
