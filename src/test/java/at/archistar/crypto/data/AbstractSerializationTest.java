package at.archistar.crypto.data;

import at.archistar.crypto.exceptions.WeakSecurityException;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.Arrays;
import static org.fest.assertions.api.Assertions.assertThat;
import static org.fest.assertions.api.Assertions.fail;
import org.junit.Test;

/**
 *
 * @author andy
 */
public abstract class AbstractSerializationTest {
    
    protected Share share;
    
    protected byte[] serializedShare;
    
    @Test(expected=InvalidParametersException.class)
    public void deserializingNullFails() throws InvalidParametersException, IOException {
        ShareFactory.deserialize((byte[])null);
        fail("you shouldn't be able to deserialize a share from null");
    }
    
    @Test(expected=InvalidParametersException.class)
    public void deserializingNullFails2() throws InvalidParametersException, IOException {
        ShareFactory.deserialize((DataInputStream)null);
        fail("you shouldn't be able to deserialize a share from null");
    }

    @Test(expected=InvalidParametersException.class)
    public void itFailsForDifferentVersions() throws IOException, WeakSecurityException, InvalidParametersException {
        byte[] tmp = serializedShare.clone();
        tmp[3] = 42;
        ShareFactory.deserialize(tmp);
        fail("this should have been a different serialization format version");
    }
    
    @Test(expected=InvalidParametersException.class)
    public void itFailsIfTheresNoFullHeader() throws InvalidParametersException, IOException, WeakSecurityException {
        
        /* header should be 15 byte */
        for(int i =0; i < 15; i++) {
            byte[] tmp = Arrays.copyOf(serializedShare, i);
            ShareFactory.deserialize(tmp);
        }
        fail("without a header a reconstruction should not have been possible");
    }
    
    @Test(expected=InvalidParametersException.class)
    public void itFailsIfTheresAnUnknownType() throws IOException, WeakSecurityException, InvalidParametersException {
        byte[] tmp = serializedShare.clone();
        tmp[4] = 99;
        ShareFactory.deserialize(tmp);
        fail("without a valid type a reconstruction should not have been possible");
    }
    
    @Test
    public void testDeserialize() throws IOException, WeakSecurityException, InvalidParametersException {
        Share deserialized = ShareFactory.deserialize(serializedShare);
        assertThat(deserialized.compareTo(share)).isEqualTo(0);
        assertThat(deserialized).isEqualTo(share);
    }
    
    @Test(expected=InvalidParametersException.class)
    public void itFailsIfDataIsTooLong() throws IOException, WeakSecurityException, InvalidParametersException {
        byte[] tmp = Arrays.copyOf(serializedShare, serializedShare.length + 20);
        ShareFactory.deserialize(tmp);
        fail("there was much data for this type of share");
    }

    @Test(expected=InvalidParametersException.class)
    public void itFailsIfDataIsTooShort() throws IOException, WeakSecurityException, InvalidParametersException {
        byte[] tmp = Arrays.copyOf(serializedShare, serializedShare.length - 1);
        ShareFactory.deserialize(tmp);
        fail("there was not enough data for this type of share");
    }
}
