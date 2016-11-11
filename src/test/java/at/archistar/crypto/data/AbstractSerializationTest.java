package at.archistar.crypto.data;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;

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

    /** correct metadata for "this.share" */
    protected HashMap<String, String> metaData;

    /**
     * deserializing null should fail
     *
     * @throws at.archistar.crypto.data.InvalidParametersException this should be thrown
     * @throws java.io.IOException this shouldn't be thrown
     */
    @Test(expected = InvalidParametersException.class)
    public void deserializingNullFails() throws InvalidParametersException, IOException {
        ShareFactory.deserialize(null, null);
        fail("you shouldn't be able to deserialize a share from null");
    }

    /**
     * deserializing empty data should fail
     *
     * @throws at.archistar.crypto.data.InvalidParametersException this should be thrown
     * @throws java.io.IOException this shouldn't be thrown
     */
    @Test(expected = InvalidParametersException.class)
    public void deserializingEmptyData() throws InvalidParametersException, IOException {
        ShareFactory.deserialize(new byte[0], new HashMap<String, String>());
        fail("you shouldn't be able to deserialize a share from empty data");
    }

    /**
     * deserializing an invalid share-on-disk version should fail.
     *
     * @throws at.archistar.crypto.data.InvalidParametersException this should be thrown
     * @throws java.io.IOException this shouldn't be thrown
     */
    @Test(expected = InvalidParametersException.class)
    public void itFailsForDifferentVersions() throws IOException, InvalidParametersException {
        HashMap<String, String> tmp = (HashMap<String, String>) metaData.clone();
        tmp.put("archistar-version","1");
        ShareFactory.deserialize(serializedShare, tmp);
        fail("this should have been a different serialization format version");
    }

    /**
     * Deserializing shares with incomplete metadata should fail
     *
     * @throws at.archistar.crypto.data.InvalidParametersException this should be thrown
     * @throws java.io.IOException this shouldn't be thrown
     */
    @Test(expected = InvalidParametersException.class)
    public void itFailsIfTheresNoCompleteMetaData() throws InvalidParametersException, IOException {
        ShareFactory.deserialize(serializedShare, new HashMap<String, String>());
        fail("without a header a reconstruction should not have been possible");
    }

    /**
     * deserializing an unknown share type should fail.
     *
     * @throws at.archistar.crypto.data.InvalidParametersException this should be thrown
     * @throws java.io.IOException this shouldn't be thrown
     */
    @Test(expected = InvalidParametersException.class)
    public void itFailsIfTheresAnUnknownType() throws IOException, InvalidParametersException {
        HashMap<String, String> tmp = (HashMap<String, String>) metaData.clone();
        tmp.put("archistar-share-type", "XYZ");
        ShareFactory.deserialize(serializedShare, tmp);
        fail("without a valid type a reconstruction should not have been possible");
    }

    /**
     * Test if deserialization yields the same object
     *
     * @throws at.archistar.crypto.data.InvalidParametersException shouldn't be thrown
     * @throws java.io.IOException this shouldn't be thrown
     */
    @Test
    public void testDeserialize() throws IOException, InvalidParametersException {
        Share deserialized = ShareFactory.deserialize(serializedShare, metaData);
        assertThat(deserialized.compareTo(share)).isEqualTo(0);
        assertThat(deserialized).isEqualTo(share);
    }

    /**
     * test if there's an exception if there's additional data after the
     * serialized share
     *
     * @throws at.archistar.crypto.data.InvalidParametersException this should be thrown
     * @throws java.io.IOException this shouldn't be thrown
     */
    @Test(expected = InvalidParametersException.class)
    public void itFailsIfDataIsTooLong() throws IOException, InvalidParametersException {
        byte[] tmp = Arrays.copyOf(serializedShare, serializedShare.length + 20);
        ShareFactory.deserialize(tmp, metaData);
        fail("there was much data for this type of share");
    }

    /**
     * test if we can pass in partial shares
     * without IC, we should - with IC we should not
     *
     * @throws at.archistar.crypto.data.InvalidParametersException this shouldn't be thrown
     * @throws java.io.IOException this shouldn't be thrown
     */
    @Test
    public void failingWithPartialShares() throws IOException, InvalidParametersException {
        byte[] tmp = Arrays.copyOf(serializedShare, serializedShare.length - 1);
        Share s = ShareFactory.deserialize(tmp, metaData);
        assertThat(s).isNotNull();
    }
}
