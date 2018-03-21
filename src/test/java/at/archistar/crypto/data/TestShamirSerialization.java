package at.archistar.crypto.data;

import java.io.IOException;

import org.junit.Before;
import org.junit.Test;

import static org.fest.assertions.api.Assertions.assertThat;

/**
 * Perform serialization tests upon Shamir shares
 */
public class TestShamirSerialization extends AbstractSerializationTest {
    @Before
    public void setupData() throws InvalidParametersException, IOException {
        share = new ShamirShare((byte) 7, new byte[]{1,2,3});
        metaData = share.getMetaData();
        serializedShare = share.getSerializedData();
    }

    /**
     * Deserializing an empty Share (i.e. data.length == 0) should not fail
     */
    @Test
    public void deserializingEmptyShare() throws InvalidParametersException, IOException {
        Share s0 = new ShamirShare((byte) 3, new byte[]{});

        Share s1 = ShareFactory.deserialize(s0.getSerializedData(), s0.getMetaData());

        assertThat(s0).isEqualTo(s1);
    }
}
