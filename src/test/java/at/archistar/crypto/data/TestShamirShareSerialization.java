package at.archistar.crypto.data;

import java.io.IOException;
import org.junit.Test;
import static org.fest.assertions.api.Assertions.*;

import at.archistar.crypto.exceptions.WeakSecurityException;
import org.bouncycastle.util.Arrays;
import org.junit.Before;

/**
 * This class tests Shamir share serialization.
 */
public class TestShamirShareSerialization {

    private ShamirShare s;
    private byte[] serialized;
    
    @Before
    public void prepareData() throws InvalidParametersException, IOException {
        s = new ShamirShare((byte) 7, new byte[]{1, 2, 3, 4, 5});
        serialized = s.serialize();
    }
    
    @Test
    public void theSerializedObjectShouldBeTheSame() throws IOException, WeakSecurityException, InvalidParametersException {
        ShamirShare deserialized = (ShamirShare) SerializableShare.deserialize(serialized);
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
