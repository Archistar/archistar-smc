package at.archistar.crypto.data;

import java.io.IOException;

import org.junit.Before;

/**
 * Perform serialization tests upon Krawcywk shares
 */
public class TestKrawczykSerialization extends AbstractSerializationTest {
    @Before
    public void setupData() throws InvalidParametersException, IOException {
        final byte[] key = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,
                21,22,23,24,25,26,27,28,29,30,31,32};
        share = new KrawczykShare((byte) 7, new byte[]{1,2,3}, 10, 1, key);
        metaData = share.getMetaData();
        serializedShare = share.getSerializedData();
    }
}
