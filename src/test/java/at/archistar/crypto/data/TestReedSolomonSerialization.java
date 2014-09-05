package at.archistar.crypto.data;

import at.archistar.crypto.exceptions.WeakSecurityException;
import java.io.IOException;
import org.bouncycastle.util.Arrays;
import static org.fest.assertions.api.Assertions.assertThat;
import static org.fest.assertions.api.Assertions.assertThat;
import static org.fest.assertions.api.Assertions.fail;
import org.junit.Before;
import org.junit.Test;

/**
 * This class tests Reed-Solomon Share serialization.
 */
public class TestReedSolomonSerialization {
    
    private ReedSolomonShare s;
    private byte[] serialized;
    
    @Before
    public void prepareData() throws InvalidParametersException, IOException {
        s = new ReedSolomonShare((byte) 7, new byte[]{1, 2, 3, 4, 5}, 100);
        serialized = s.serialize();
    }

    @Test
    public void testReedSolomonShareSerialization() throws IOException, WeakSecurityException, InvalidParametersException {
        ReedSolomonShare deserialized = (ReedSolomonShare) SerializableShare.deserialize(serialized);
        assertThat(deserialized.compareTo(s)).isEqualTo(0);
        assertThat(deserialized).isEqualTo(s);
    }
    
    @Test(expected=InvalidParametersException.class)
    public void itFailsIfDataIsTooLong() throws IOException, WeakSecurityException, InvalidParametersException {
        byte[] tmp = Arrays.copyOf(serialized, serialized.length + 20);
        SerializableShare.deserialize(tmp);
        fail("there was much data for this type of share");
    }

    @Test(expected=InvalidParametersException.class)
    public void itFailsIfDataIsTooShort() throws IOException, WeakSecurityException, InvalidParametersException {
        byte[] tmp = Arrays.copyOf(serialized, serialized.length -1);
        SerializableShare.deserialize(tmp);
        fail("there was not enough data for this type of share");
    }
}
