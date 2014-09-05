package at.archistar.crypto.data;

import java.io.IOException;
import org.junit.Test;

import at.archistar.crypto.data.KrawczykShare.EncryptionAlgorithm;
import at.archistar.crypto.exceptions.WeakSecurityException;
import static org.fest.assertions.api.Assertions.assertThat;

/**
 * This class tests serialization.
 */
public class TestKrawcywkSerialization {

    @Test
    public void testKrawczykShareSerialization() throws IOException, WeakSecurityException, InvalidParametersException {
        KrawczykShare s = new KrawczykShare((byte) 7, new byte[]{1, 2, 3, 4, 5}, 100, new byte[]{1, 2, 3, 4, 5}, EncryptionAlgorithm.AES);
        byte[] serialized = s.serialize();
        KrawczykShare deserialized = (KrawczykShare) SerializableShare.deserialize(serialized);
        assertThat(deserialized.compareTo(s)).isEqualTo(0);
        assertThat(deserialized).isEqualTo(s);
    }
    
    /* TODO: need more tests for data-length */
}
