package at.archistar.crypto.data;

import java.util.HashMap;
import java.util.Map;
import org.junit.Test;
import static org.fest.assertions.api.Assertions.*;

/**
 * test validity of shares
 */
public class TestShareValidation {
    
    private static final byte[] data = {1, 2, 3};
    private static final Map<Byte, Integer> emptyMetadata = new HashMap<>();
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
        Map<Byte, Integer> metadata = new HashMap<>();
        metadata.put(KrawczykShare.KEY_ENC_ALGORITHM, 1);

        Share share = ShareFactory.createKrawczyk((byte)7, data, data , metadata);
        assertThat(share).isNotNull();    }
    
    @Test
    public void allowValidRabinConstruction() throws InvalidParametersException {
        Map<Byte, Integer> metadata = new HashMap<>();
        metadata.put((byte)1, 1);
        Share share = ShareFactory.create(Share.ShareType.REED_SOLOMON, (byte)7,
                                data, metadata);
        assertThat(share).isNotNull();
    }
    
    @Test
    public void allowValidKrawczwkConstruction() throws InvalidParametersException {
        Map<Byte, Integer> metadata = new HashMap<>();
        metadata.put(KrawczykShare.KEY_ENC_ALGORITHM, 1);
        metadata.put(KrawczykShare.KEY_ORIGINAL_LENGTH, 1);
        
        Share share = ShareFactory.createKrawczyk((byte)7, data, data , metadata);
        assertThat(share).isNotNull();
    }

    
    @Test(expected=InvalidParametersException.class)
    public void KrawczykAlgMustNotBeNull() throws InvalidParametersException {
        Map<Byte, Integer> metadata = new HashMap<>();
        metadata.put(KrawczykShare.KEY_ORIGINAL_LENGTH, 1);

        Share share = ShareFactory.createKrawczyk((byte)7, data, data , metadata);
        assertThat(share).isNotNull();
    }

    @Test(expected=InvalidParametersException.class)
    public void KrawczykKeyYMustNotBeNull() throws InvalidParametersException {
        
        Map<Byte, Integer> metadata = new HashMap<>();
        metadata.put(KrawczykShare.KEY_ORIGINAL_LENGTH, 1);
        metadata.put(KrawczykShare.KEY_ENC_ALGORITHM, 1);

        Share share = ShareFactory.createKrawczyk((byte) 7, data, null, metadata);
        assertThat(share).isNotNull();
    }
}
