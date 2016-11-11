package at.archistar.crypto.data;

import java.io.IOException;

import org.junit.Before;

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
}
