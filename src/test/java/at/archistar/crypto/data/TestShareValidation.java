package at.archistar.crypto.data;

import static at.archistar.crypto.data.Share.ENC_ALGORITHM;
import static at.archistar.crypto.data.Share.ENC_KEY;
import static at.archistar.crypto.data.Share.ORIGINAL_LENGTH;
import static at.archistar.crypto.data.Share.ShareType.KRAWCZYK;
import static at.archistar.crypto.data.Share.ShareType.REED_SOLOMON;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;
import org.junit.Test;
import static org.fest.assertions.api.Assertions.*;

/**
 * test validity of shares
 */
public class TestShareValidation {
    
    private static final byte[] data = {1, 2, 3};
    private static final Map<Byte, byte[]> emptyMetadata = new HashMap<>();
    private static final Map<Byte, byte[]> emptyMacs = new HashMap<>();
    
    @Test(expected=InvalidParametersException.class)
    public void xMustNotBe0() throws InvalidParametersException {
        Share share = ShareFactory.create(Share.ShareType.SHAMIR, (byte)0,
                                          data, emptyMetadata);
        assertThat(share).isNotNull();
    }
    
    @Test(expected=InvalidParametersException.class)
    public void yMustNotBeNull() throws InvalidParametersException {
        Share share = ShareFactory.create(Share.ShareType.SHAMIR, (byte)7,
                                          null, emptyMetadata);
        assertThat(share).isNotNull();
    }

    @Test
    public void allowValidShamirConstruction() throws InvalidParametersException {
        Share share = ShareFactory.create(Share.ShareType.SHAMIR, (byte)7,
                                          data, emptyMetadata);
        assertThat(share).isNotNull();
    }
    
    @Test(expected=InvalidParametersException.class)
    public void ShamirMetadataMustNotBeNull() throws InvalidParametersException {
        Share share = ShareFactory.create(Share.ShareType.SHAMIR, (byte)7,
                                          data, null);
        assertThat(share).isNotNull();
    }
    
    @Test(expected=InvalidParametersException.class)
    public void RabinMustHaveOriginalLength() throws InvalidParametersException {
        Share share = ShareFactory.create(Share.ShareType.REED_SOLOMON, (byte)7,
                                          data, emptyMetadata);
        assertThat(share).isNotNull();
    }
    
    @Test(expected=InvalidParametersException.class)
    public void KrawcywkMustHaveOriginalLength() throws InvalidParametersException {
        Map<Byte, byte[]> metadata = new HashMap<>();
        metadata.put(ENC_ALGORITHM, ByteBuffer.allocate(4).putInt(1).array());
        metadata.put(ENC_KEY, data);
        
        Share share = ShareFactory.create(Share.ShareType.KRAWCZYK, (byte)7, data , metadata);
        assertThat(share).isNotNull();
    }
    
    @Test
    public void allowValidRabinConstruction() throws InvalidParametersException {
        Map<Byte, byte[]> metadata = new HashMap<>();
        metadata.put(ORIGINAL_LENGTH, ByteBuffer.allocate(4).putInt(1).array());

        Share share = ShareFactory.create(REED_SOLOMON, (byte)7, data, metadata);
        assertThat(share).isNotNull();
    }
    
    @Test
    public void allowValidKrawczwkConstruction() throws InvalidParametersException {
        Map<Byte, byte[]> metadata = new HashMap<>();
        metadata.put(ENC_ALGORITHM, ByteBuffer.allocate(4).putInt(1).array());
        metadata.put(ENC_KEY, data);
        metadata.put(ORIGINAL_LENGTH, ByteBuffer.allocate(4).putInt(1).array());
        
        Share share = ShareFactory.create(KRAWCZYK, (byte)7, data , metadata);
        assertThat(share).isNotNull();
    }

    
    @Test(expected=InvalidParametersException.class)
    public void KrawczykAlgMustNotBeNull() throws InvalidParametersException {
        Map<Byte, byte[]> metadata = new HashMap<>();
        metadata.put(ENC_KEY, data);
        metadata.put(ORIGINAL_LENGTH, ByteBuffer.allocate(4).putInt(1).array());

        Share share = ShareFactory.create(KRAWCZYK, (byte)7, data, metadata);
        assertThat(share).isNotNull();
    }

    @Test(expected=InvalidParametersException.class)
    public void KrawczykKeyYMustNotBeNull() throws InvalidParametersException {
        
        Map<Byte, byte[]> metadata = new HashMap<>();
        metadata.put(ENC_ALGORITHM, ByteBuffer.allocate(4).putInt(1).array());
        metadata.put(ORIGINAL_LENGTH, ByteBuffer.allocate(4).putInt(1).array());

        Share share = ShareFactory.create(KRAWCZYK, (byte) 7, data, metadata);
        assertThat(share).isNotNull();
    }
}
