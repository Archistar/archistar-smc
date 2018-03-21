package at.archistar.crypto.data;

import java.io.IOException;

import static org.fest.assertions.api.Assertions.assertThat;
import org.junit.Before;
import org.junit.Test;

/**
 * Perform serialization tests upon Reed-Solomon shares
 */
public class TestRabinSerialization extends AbstractSerializationTest {
    @Before
    public void setupData() throws InvalidParametersException, IOException {
        share = new RabinShare((byte) 7, new byte[]{1,2,3}, 10);
        metaData = share.getMetaData();
        serializedShare = share.getSerializedData();
    }

    /**
     * Deserializing an empty Share (i.e. data.length == 0) should not fail
     */
    @Test
    public void deserializingEmptyShare() throws InvalidParametersException, IOException {
        Share s0 = new RabinShare((byte) 3, new byte[]{}, 0);

        Share s1 = ShareFactory.deserialize(s0.getSerializedData(), s0.getMetaData());

        assertThat(s0).isEqualTo(s1);
    }
}
