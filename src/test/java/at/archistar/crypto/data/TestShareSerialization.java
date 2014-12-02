package at.archistar.crypto.data;

import at.archistar.crypto.exceptions.WeakSecurityException;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import static org.fest.assertions.api.Assertions.*;
import org.junit.Before;
import org.junit.Test;

public class TestShareSerialization {
    
    private Share share;
    
    private byte[] shareSerialized;
    
    @Before
    public void initializeStuff() throws InvalidParametersException, IOException {
        Map<Byte, Integer> metadata = new HashMap<>();
        metadata.put((byte)1, 1);
        share = ShareFactory.create(Share.ShareType.REED_SOLOMON, (byte)7,
                                    new byte[]{1,2,3}, metadata);
        
        this.shareSerialized = share.serialize();
    }
    
    /**
     * compare to initial result, should never change
     */
    @Test
    public void serializationShouldStayTheSame() {
        assertThat(this.shareSerialized).isEqualTo(new byte[] {0, 0, 0, 3, 1, 0, 7, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 3, 1, 2, 3});
    }
    
    @Test(expected=InvalidParametersException.class)
    public void deserializingNullFails() throws InvalidParametersException, IOException {
        ShareFactory.deserialize((byte[])null);
        fail("you shouldn't be able to deserialize a share from null");
    }
    
    @Test(expected=InvalidParametersException.class)
    public void deserializingNullFails2() throws InvalidParametersException, IOException {
        ShareFactory.deserialize((DataInputStream)null);
        fail("you shouldn't be able to deserialize a share from null");
    }

    @Test(expected=InvalidParametersException.class)
    public void itFailsForDifferentVersions() throws IOException, WeakSecurityException, InvalidParametersException {
        byte[] tmp = Arrays.copyOf(shareSerialized, shareSerialized.length);
        tmp[3] = 42;
        ShareFactory.deserialize(tmp);
        fail("this should have been a different serialization format version");
    }
    
    @Test(expected=InvalidParametersException.class)
    public void itFailsIfTheresNoFullHeader() throws InvalidParametersException, IOException, WeakSecurityException {
        
        /* header should be 9 byte */
        for(int i =0; i < 9; i++) {
            byte[] tmp = Arrays.copyOf(shareSerialized, i);
            ShareFactory.deserialize(tmp);
        }
        fail("without a header a reconstruction should not have been possible");
    }
    
    @Test(expected=InvalidParametersException.class)
    public void itFailsIfTheresAnUnknownType() throws IOException, WeakSecurityException, InvalidParametersException {
        byte[] tmp = Arrays.copyOf(shareSerialized, shareSerialized.length);
        tmp[4] = 99;
        ShareFactory.deserialize(tmp);
        fail("without a valid type a reconstruction should not have been possible");
    }
    
    @Test
    public void testShamirCycle() throws IOException, WeakSecurityException, InvalidParametersException {
        Share deserialized = ShareFactory.deserialize(shareSerialized);
        assertThat(deserialized.compareTo(share)).isEqualTo(0);
        assertThat(deserialized).isEqualTo(share);
    }
    
    @Test(expected=InvalidParametersException.class)
    public void itFailsIfDataIsTooLong() throws IOException, WeakSecurityException, InvalidParametersException {
        byte[] tmp = Arrays.copyOf(shareSerialized, shareSerialized.length + 20);
        ShareFactory.deserialize(tmp);
        fail("there was much data for this type of share");
    }

    @Test(expected=InvalidParametersException.class)
    public void itFailsIfDataIsTooShort() throws IOException, WeakSecurityException, InvalidParametersException {
        byte[] tmp = Arrays.copyOf(shareSerialized, shareSerialized.length - 1);
        ShareFactory.deserialize(tmp);
        fail("there was not enough data for this type of share");
    }
    
    @Test
    public void testVSSShareSerialization() throws WeakSecurityException, IOException, InvalidParametersException {

        Map<Byte, byte[]> macs = new HashMap<>();
        macs.put((byte) 1, new byte[]{1, 2, 3});
        macs.put((byte) 2, new byte[]{4, 5, 6});

        Map<Byte, byte[]> macKeys = new HashMap<>();
        macKeys.put((byte) 1, new byte[]{7, 8, 9});
        macKeys.put((byte) 2, new byte[]{10, 11, 12});
        
        Map<Byte, Integer> metadata = new HashMap<>();
        metadata.put((byte)1, 1);
        Share s = ShareFactory.create(Share.ShareType.REED_SOLOMON, (byte)7,
                                      new byte[] {1, 2, 3}, metadata,
                                      Share.ICType.RABIN_BEN_OR, macKeys, macs);

        byte[] serialized = s.serialize();
        Share deserialized = ShareFactory.deserialize(serialized);
        
        assertThat(deserialized.compareTo(s)).isEqualTo(0);
        assertThat(deserialized).isEqualTo(s);
    }
    
    private Share s;
    
    private byte[] serialized;
    
    @Before
    public void prepareData() throws InvalidParametersException, IOException {
        Map<Byte, Integer> metadata = new HashMap<>();
        metadata.put(KrawczykShare.KEY_ORIGINAL_LENGTH, 1);

        s = ShareFactory.create(Share.ShareType.REED_SOLOMON, (byte) 7, new byte[]{1, 2, 3, 4, 5}, metadata);
        serialized = s.serialize();
    }

    @Test
    public void testReedSolomonShareSerialization() throws IOException, WeakSecurityException, InvalidParametersException {
        Share deserialized = ShareFactory.deserialize(serialized);
        assertThat(deserialized.compareTo(s)).isEqualTo(0);
        assertThat(deserialized).isEqualTo(s);
    }
    
    @Test(expected=InvalidParametersException.class)
    public void RabinFailsIfDataIsTooLong() throws IOException, WeakSecurityException, InvalidParametersException {
        byte[] tmp = Arrays.copyOf(serialized, serialized.length + 20);
        ShareFactory.deserialize(tmp);
        fail("there was much data for this type of share");
    }

    @Test(expected=InvalidParametersException.class)
    public void RabinFailsIfDataIsTooShort() throws IOException, WeakSecurityException, InvalidParametersException {
        byte[] tmp = Arrays.copyOf(serialized, serialized.length -1);
        ShareFactory.deserialize(tmp);
        fail("there was not enough data for this type of share");
    }

    @Test
    public void testKrawczykShareSerialization() throws IOException, WeakSecurityException, InvalidParametersException {
        Map<Byte, Integer> metadata = new HashMap<>();
        metadata.put(KrawczykShare.KEY_ENC_ALGORITHM, 1);
        metadata.put(KrawczykShare.KEY_ORIGINAL_LENGTH, 1);

        Share s = ShareFactory.createKrawczyk((byte) 7, new byte[]{1, 2, 3, 4, 5}, new byte[]{1, 2, 3}, metadata);
        byte[] serialized = s.serialize();
        Share deserialized = ShareFactory.deserialize(serialized);
        
        assertThat(deserialized.compareTo(s)).isEqualTo(0);
        assertThat(deserialized).isEqualTo(s);
    }
}
