package at.archistar.crypto.data;

import static at.archistar.crypto.data.Share.ORIGINAL_LENGTH;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;
import static org.fest.assertions.api.Assertions.assertThat;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author andy
 */
public class TestRabinSerialization extends AbstractSerializationTest {
    @Before
    public void setupData() throws InvalidParametersException, IOException {
        Map<Byte, byte[]> metadata = new HashMap<>();
        metadata.put(ORIGINAL_LENGTH, ByteBuffer.allocate(4).putInt(1).array());
        
        share = ShareFactory.create(Share.ShareType.REED_SOLOMON, (byte)7,
                                    new byte[]{1,2,3}, metadata);
        serializedShare = share.serialize();
    }
    
    /**
     * compare to initial result, should never change
     */
    @Test
    public void serializationShouldStayTheSame() {
        assertThat(serializedShare).isEqualTo(new byte[] {0, 0, 0, 3, 1, 0, 7, 0, 0, 0, 1, 1, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0, 3, 1, 2, 3});
    }
}
