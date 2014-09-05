package at.archistar.crypto.data;

import at.archistar.crypto.exceptions.WeakSecurityException;
import java.io.IOException;
import java.util.Arrays;
import static org.fest.assertions.api.Assertions.*;
import org.junit.Before;
import org.junit.Test;

public class SerializableShareTest {
    
    private Share share;
    
    private byte[] shareSerialized;
    
    @Before
    public void initializeStuff() throws InvalidParametersException, IOException {
        this.share = new ShamirShare((byte)42, new byte[]{1,2,3});
        this.shareSerialized = share.serialize();
    }
    
    /**
     * compare to initial result, should never change
     */
    @Test
    public void serializationShouldStayTheSame() {
        /* version(4), type(1), xValue(4), count(1), values(count) */
        assertThat(this.shareSerialized).isEqualTo(new byte[] {0, 0, 0, 2, 0, 0, 0, 0, 42, 0, 0, 0, 3, 1, 2, 3});
    }
    
    @Test(expected=InvalidParametersException.class)
    public void deserializingNullFails() throws IOException, WeakSecurityException, InvalidParametersException {
        SerializableShare.deserialize(null);
        fail("you shouldn't be able to deserialize a share from null");
    }
    
    @Test(expected=InvalidParametersException.class)
    public void itFailsForDifferentVersions() throws IOException, WeakSecurityException, InvalidParametersException {
        byte[] tmp = Arrays.copyOf(shareSerialized, shareSerialized.length);
        tmp[3] = 42;
        SerializableShare.deserialize(tmp);
        fail("this should have been a different serialization format version");
    }
    
    @Test(expected=InvalidParametersException.class)
    public void itFailsIfTheresNoFullHeader() throws InvalidParametersException, IOException, WeakSecurityException {
        
        /* header should be 9 byte */
        for(int i =0; i < 9; i++) {
            byte[] tmp = Arrays.copyOf(shareSerialized, i);
            SerializableShare.deserialize(tmp);
        }
        fail("without a header a reconstruction should not have been possible");
    }
    
    @Test(expected=InvalidParametersException.class)
    public void itFailsIfTheresAnUnknownType() throws IOException, WeakSecurityException, InvalidParametersException {
        byte[] tmp = Arrays.copyOf(shareSerialized, shareSerialized.length);
        tmp[4] = 99;
        SerializableShare.deserialize(tmp);
        fail("without a valid type a reconstruction should not have been possible");
    }
}
