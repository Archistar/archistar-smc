package at.archistar.crypto.data;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import org.junit.Test;

import at.archistar.crypto.exceptions.WeakSecurityException;
import static org.fest.assertions.api.Assertions.assertThat;

/**
 * This class tests VSS Share serialization.
 */
public class TestVSSShareSerialization {

    @Test
    public void testVSSShareSerialization() throws WeakSecurityException, IOException, InvalidParametersException {

        ShamirShare s = new ShamirShare((byte) 7, new byte[]{1, 2, 3, 4, 5});
        Map<Byte, byte[]> macs = new HashMap<>();
        macs.put((byte) 1, new byte[]{1, 2, 3});
        macs.put((byte) 2, new byte[]{4, 5, 6});

        Map<Byte, byte[]> macKeys = new HashMap<>();
        macKeys.put((byte) 1, new byte[]{7, 8, 9});
        macKeys.put((byte) 2, new byte[]{10, 11, 12});

        VSSShare vss = new VSSShare(s, macs, macKeys);

        byte[] serialized = vss.serialize();
        VSSShare deserialized = (VSSShare) SerializableShare.deserialize(serialized);
        
        assertThat(deserialized.compareTo(vss)).isEqualTo(0);
        assertThat(deserialized).isEqualTo(vss);
    }
    
    /* TODO: need more tests for data-length */
}
