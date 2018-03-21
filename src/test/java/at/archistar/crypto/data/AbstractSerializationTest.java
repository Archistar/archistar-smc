package at.archistar.crypto.data;

import org.junit.Test;

import java.util.Arrays;
import java.util.HashMap;

import static org.fest.assertions.api.Assertions.assertThat;

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
     * Deserializing null should fail
     */
    @Test
    public void deserializingNullFails() {
        Share s = ShareFactory.deserialize(null, null);
        assertThat(s).isExactlyInstanceOf(BrokenShare.class);
    }

    /**
     * Deserializing empty data should fail
     */
    @Test
    public void deserializingEmptyData() {
        Share s = ShareFactory.deserialize(new byte[0], new HashMap<>());
        assertThat(s).isExactlyInstanceOf(BrokenShare.class);
    }

    /**
     * Deserializing an invalid share-on-disk version should fail.
     */
    @Test
    public void itFailsForDifferentVersions() {
        HashMap<String, String> tmp = new HashMap<>(metaData);
        tmp.put("archistar-version","1");
        Share s = ShareFactory.deserialize(serializedShare, tmp);
        assertThat(s).isExactlyInstanceOf(BrokenShare.class);
    }

    /**
     * Deserializing shares with incomplete metadata should fail
     */
    @Test
    public void itFailsIfTheresNoCompleteMetaData() {
        Share s = ShareFactory.deserialize(serializedShare, new HashMap<>());
        assertThat(s).isExactlyInstanceOf(BrokenShare.class);
    }

    /**
     * Deserializing an unknown share type should fail
     */
    @Test
    public void itFailsIfTheresAnUnknownType() {
        HashMap<String, String> tmp = new HashMap<>(metaData);
        tmp.put("archistar-share-type", "XYZ");
        Share s = ShareFactory.deserialize(serializedShare, tmp);
        assertThat(s).isExactlyInstanceOf(BrokenShare.class);
    }

    /**
     * Test if deserialization yields the same object
     */
    @Test
    public void testDeserialize() {
        Share deserialized = ShareFactory.deserialize(serializedShare, metaData);
        assertThat(deserialized.compareTo(share)).isEqualTo(0);
        assertThat(deserialized).isEqualTo(share);
    }

    /**
     * Test if we get a BrokenShare if there's additional data after the serialized share
     */
    @Test
    public void itFailsIfDataIsTooLong() {
        byte[] tmp = Arrays.copyOf(serializedShare, serializedShare.length + 20);
        Share s = ShareFactory.deserialize(tmp, metaData);
        assertThat(s).isExactlyInstanceOf(BrokenShare.class);
    }

    /**
     * Test if we can pass in partial shares
     * without IC, we should - with IC we should not
     */
    @Test
    public void failingWithPartialShares() {
        byte[] tmp = Arrays.copyOf(serializedShare, serializedShare.length - 1);
        Share s = ShareFactory.deserialize(tmp, metaData);
        assertThat(s).isNotNull();
    }
}
