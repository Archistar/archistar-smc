package at.archistar.crypto.data;

import java.io.IOException;

import org.junit.Before;

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
}
