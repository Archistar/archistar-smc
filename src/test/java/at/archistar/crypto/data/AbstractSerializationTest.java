package at.archistar.crypto.data;

import java.io.DataInputStream;
import java.io.IOException;
import java.util.Arrays;
import static org.fest.assertions.api.Assertions.assertThat;
import static org.fest.assertions.api.Assertions.fail;
import org.junit.Test;

/**
 * Base class that all (De-)serialization tests will inherit from. This was written
 * to reduce duplicate testing code.
 */
public abstract class AbstractSerializationTest {

    /** the to-be-tested share */
    protected Share share;
    
    /** a correctly serialized "this.share" */
    protected byte[] serializedShare;
    
    /**
     * deserializing null should fail. This tests the byte[] method
     * @throws at.archistar.crypto.data.InvalidParametersException this should be thrown
     * @throws java.io.IOException this shouldn't be thrown
     */
    @Test(expected=InvalidParametersException.class)
    public void deserializingNullFails() throws InvalidParametersException, IOException {
        ShareFactory.deserialize((byte[])null);
        fail("you shouldn't be able to deserialize a share from null");
    }

    /**
     * deserializing null should fail. This tests the DataInputStream Method
     * @throws at.archistar.crypto.data.InvalidParametersException this should be thrown
     * @throws java.io.IOException this shouldn't be thrown
     */
    @Test(expected=InvalidParametersException.class)
    public void deserializingNullFails2() throws InvalidParametersException, IOException {
        ShareFactory.deserialize((DataInputStream)null);
        fail("you shouldn't be able to deserialize a share from null");
    }

    /**
     * deserializing an invalid share-ondisk version should fail.
     * @throws at.archistar.crypto.data.InvalidParametersException this should be thrown
     * @throws java.io.IOException this shouldn't be thrown
     */
    @Test(expected=InvalidParametersException.class)
    public void itFailsForDifferentVersions() throws IOException, InvalidParametersException {
        byte[] tmp = serializedShare.clone();
        tmp[3] = 42;
        ShareFactory.deserialize(tmp);
        fail("this should have been a different serialization format version");
    }

    /**
     * Our header has at least 15 byte. Deserializing byte-arrays smaller than
     * that should fail.
     * @throws at.archistar.crypto.data.InvalidParametersException this should be thrown
     * @throws java.io.IOException this shouldn't be thrown
     */
    @Test(expected=InvalidParametersException.class)
    public void itFailsIfTheresNoFullHeader() throws InvalidParametersException, IOException {
        
        /* header should be 15 byte */
        for(int i =0; i < 15; i++) {
            byte[] tmp = Arrays.copyOf(serializedShare, i);
            ShareFactory.deserialize(tmp);
        }
        fail("without a header a reconstruction should not have been possible");
    }

    /**
     * deserializing an unknown share type should fail.
     * @throws at.archistar.crypto.data.InvalidParametersException this should be thrown
     * @throws java.io.IOException this shouldn't be thrown
     */
    @Test(expected=InvalidParametersException.class)
    public void itFailsIfTheresAnUnknownType() throws IOException, InvalidParametersException {
        byte[] tmp = serializedShare.clone();
        tmp[4] = 99;
        ShareFactory.deserialize(tmp);
        fail("without a valid type a reconstruction should not have been possible");
    }

    /**
     * Test if deserialization yields the same object
     * @throws at.archistar.crypto.data.InvalidParametersException shouldn't be thrown
     * @throws java.io.IOException this shouldn't be thrown
     */
    @Test
    public void testDeserialize() throws IOException, InvalidParametersException {
        Share deserialized = ShareFactory.deserialize(serializedShare);
        assertThat(deserialized.compareTo(share)).isEqualTo(0);
        assertThat(deserialized).isEqualTo(share);
    }

    /**
     * test if an short-read produces an exception
     * @throws at.archistar.crypto.data.InvalidParametersException this should be thrown
     * @throws java.io.IOException this shouldn't be thrown
     */
    @Test(expected=InvalidParametersException.class)
    public void itFailsIfDataIsTooLong() throws IOException, InvalidParametersException {
        byte[] tmp = Arrays.copyOf(serializedShare, serializedShare.length + 20);
        ShareFactory.deserialize(tmp);
        fail("there was much data for this type of share");
    }

    /**
     * test if there's an exception if there's additional data after the
     * serialized share
     * 
     * @throws at.archistar.crypto.data.InvalidParametersException this should be thrown
     * @throws java.io.IOException this shouldn't be thrown
     */
    @Test(expected=InvalidParametersException.class)
    public void itFailsIfDataIsTooShort() throws IOException, InvalidParametersException {
        byte[] tmp = Arrays.copyOf(serializedShare, serializedShare.length - 1);
        ShareFactory.deserialize(tmp);
        fail("there was not enough data for this type of share");
    }
}
