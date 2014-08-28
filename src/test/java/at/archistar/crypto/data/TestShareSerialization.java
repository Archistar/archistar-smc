package at.archistar.crypto.data;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

import at.archistar.crypto.data.KrawczykShare.EncryptionAlgorithm;
import at.archistar.crypto.exceptions.WeakSecurityException;
import java.io.IOException;

/**
 * <p>
 * This class tests serialization and validity of the different share-types.</p>
 *
 * It also tests creating invalid shares and deserializing invalid shares.
 *
 * @author Elias Frantar
 * @version 2014-7-24
 */
public class TestShareSerialization {

    /* test serialization */
    @Test
    public void testShamirShareSerialization() throws IOException, WeakSecurityException {
        ShamirShare s = new ShamirShare((byte) 7, new byte[]{1, 2, 3, 4, 5});
        byte[] serialized = s.serialize();
        ShamirShare deserialized = (ShamirShare) SerializableShare.deserialize(serialized);

        assert equals(deserialized, s);
    }

    @Test
    public void testReedSolomonShareSerialization() throws IOException, WeakSecurityException {
        ReedSolomonShare s = new ReedSolomonShare((byte) 7, new byte[]{1, 2, 3, 4, 5}, 100);
        byte[] serialized = s.serialize();
        ReedSolomonShare deserialized = (ReedSolomonShare) SerializableShare.deserialize(serialized);
        assert equals(deserialized, s);
    }

    @Test
    public void testKrawczykShareSerialization() throws IOException, WeakSecurityException {
        KrawczykShare s = new KrawczykShare((byte) 7, new byte[]{1, 2, 3, 4, 5}, 100, new byte[]{1, 2, 3, 4, 5}, EncryptionAlgorithm.AES);
        byte[] serialized = s.serialize();
        KrawczykShare deserialized = (KrawczykShare) SerializableShare.deserialize(serialized);
        assert equals(deserialized, s);
    }

    @Test
    public void testRabinBenOrShareSerialization() throws WeakSecurityException, IOException {

        ShamirShare s = new ShamirShare((byte) 7, new byte[]{1, 2, 3, 4, 5});
        Map<Byte, byte[]> macs = new HashMap<>();
        macs.put((byte) 1, new byte[]{1, 2, 3});
        macs.put((byte) 2, new byte[]{4, 5, 6});

        Map<Byte, byte[]> macKeys = new HashMap<>();
        macKeys.put((byte) 1, new byte[]{7, 8, 9});
        macKeys.put((byte) 2, new byte[]{10, 11, 12});

        VSSShare vss = new VSSShare(s, macs, macKeys);

        byte[] serialized = vss.serialize();
        VSSShare deserialized = (VSSShare) SerializableShare.deserialize(serialized);
        assert equals(deserialized, vss);
    }

    /*	
     @Test
     public void testDeserializeInvalidShamirShare() {
     boolean fail = true;
		
     try { // try passing null
     new ShamirShare(null);
     fail = false;
     } catch (IllegalArgumentException e) {}
     try { // try passing a too short serialization
     new ShamirShare(new byte[]{0, 0, 0, 1, 1, 2, 3, 4, 5});
     fail = false;
     } catch (IllegalArgumentException e) {}
     try { // try passing an invalid version
     new ShamirShare(new byte[]{0, 0, 0, 2, 0, 0, 0, 0, 14, 1, 2});
     fail = false;
     } catch (IllegalArgumentException e) {}
     try { // try passing an invalid type
     new ShamirShare(new byte[]{0, 0, 0, 1, 2, 0, 0, 0, 11, 1, 2});
     fail = false;
     } catch (IllegalArgumentException e) {}
     try { // try passing a share with invalid length
     new ShamirShare(new byte[]{0, 0, 0, 1, 0, 0, 0, 0, 14, 1, 2});
     fail = false;
     } catch (IllegalArgumentException e) {}
     try { // try passing an invalid share
     new ShamirShare(new byte[]{0, 0, 0, 1, 0, 0, 0, 0, 11, 0, 0});
     fail = false;
     } catch (NullPointerException e) {}
		
     assertTrue(fail);
     }
     @Test
     public void testDeserializeInvalidReedSolomonShare() {
     boolean fail = true;
		
     try { // try passing null
     new ReedSolomonShare(null);
     fail = false;
     } catch (IllegalArgumentException e) {}
     try { // try passing a too short serialization
     new ReedSolomonShare(new byte[]{0, 0, 0, 1, 1, 2, 3, 4, 5, 6});
     fail = false;
     } catch (IllegalArgumentException e) {}
     try { // try passing an invalid version
     new ReedSolomonShare(new byte[]{0, 0, 0, 2, 1, 0, 0, 0, 14, 1, 2, 3, 4, 5, 6});
     fail = false;
     } catch (IllegalArgumentException e) {}
     try { // try passing an invalid type
     new ReedSolomonShare(new byte[]{0, 0, 0, 1, 3, 0, 0, 0, 14, 1, 2, 3, 4, 5, 6});
     fail = false;
     } catch (IllegalArgumentException e) {}
     try { // try passing a share with invalid length
     new ReedSolomonShare(new byte[]{0, 0, 0, 1, 1, 0, 0, 0, 20, 1, 2, 3, 4, 5, 6, 7});
     fail = false;
     } catch (IllegalArgumentException e) {}
     try { // try passing an invalid share
     new ReedSolomonShare(new byte[]{0, 0, 0, 1, 1, 0, 0, 0, 15, 0, 0, 0, 0, 0, 0});
     fail = false;
     } catch (NullPointerException e) {}
		
     assertTrue(fail);
     }
     @Test
     public void testDeserializeInvalidKrawczykShare() {
     boolean fail = true;
		
     try { // try passing null
     new KrawczykShare(null);
     fail = false;
     } catch (IllegalArgumentException e) {}
     try { // try passing a too short serialization
     new KrawczykShare(new byte[]{0, 0, 0, 1, 1, 2, 3, 4, 5, 6, 7, 8, 9});
     fail = false;
     } catch (IllegalArgumentException e) {}
     try { // try passing an invalid type
     new KrawczykShare(new byte[]{0, 0, 0, 1, 0, 0, 0, 0, 17, 0, 1, 0, 1, 1, 2, 3, 4, 1});
     fail = false;
     } catch (IllegalArgumentException e) {}
     try { // try passing a share with invalid length
     new KrawczykShare(new byte[]{0, 0, 0, 1, 2, 0, 0, 0, 24, 0, 1, 0, 1, 1, 2, 3, 4, 1});
     fail = false;
     } catch (IllegalArgumentException e) {}
     try { // try passing an invalid share
     new KrawczykShare(new byte[]{0, 0, 0, 1, 2, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0});
     fail = false;
     } catch (NullPointerException e) {}
		
     assertTrue(fail);
     } */
    /* 
     * equals()-methods to test serialization
     * NOTE: These are not true equals-implementations! (only simple suitable ones for the test-cases)
     */
    private boolean equals(ShamirShare s1, ShamirShare s2) {
        if (s1.getId() != s2.getId()) {
            return false;
        }
        if (!Arrays.equals(s1.getY(), s2.getY())) {
            return false;
        }

        return true;
    }

    private boolean equals(ReedSolomonShare s1, ReedSolomonShare s2) {
        if (s1.getId() != s2.getId()) {
            return false;
        }
        if (!Arrays.equals(s1.getY(), s2.getY())) {
            return false;
        }
        if (s1.getOriginalLength() != s2.getOriginalLength()) {
            return false;
        }

        return true;
    }

    private boolean equals(KrawczykShare s1, KrawczykShare s2) {
        if (s1.getId() != s2.getId()) {
            return false;
        }
        if (!Arrays.equals(s1.getY(), s2.getY())) {
            return false;
        }
        if (s1.getOriginalLength() != s2.getOriginalLength()) {
            return false;
        }
        if (!Arrays.equals(s1.getKeyY(), s2.getKeyY())) {
            return false;
        }

        return true;
    }

    private boolean equals(VSSShare s1, VSSShare s2) {
        if (!equals((ShamirShare) s1.getShare(), (ShamirShare) s2.getShare())) { // hardcoded cast because we use ShamirShare in the test-case
            return false;
        }

        /* TODO: do true comparison */
        if (!s1.getMacs().keySet().equals(s2.getMacs().keySet())) {
            return false;
        }
        if (!Arrays.equals(s1.getMacs().get((byte) 1), s2.getMacs().get((byte) 1))) { // hardcoded comparison
            return false;
        }
        if (!s1.getMacKeys().keySet().equals(s2.getMacKeys().keySet())) {
            return false;
        }
        if (!Arrays.equals(s1.getMacKeys().get((byte) 1), s2.getMacKeys().get((byte) 1))) { // hardcoded comparison
            return false;
        }

        return true;
    }
}
