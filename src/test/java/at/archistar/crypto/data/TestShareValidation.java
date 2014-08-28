package at.archistar.crypto.data;

import static org.junit.Assert.*;
import org.junit.Test;

import at.archistar.crypto.data.KrawczykShare.EncryptionAlgorithm;

/**
 * <p>
 * This class tests validity of the different share-types.</p>
 */
public class TestShareValidation {

    /* test creating shares with invalid fields */
    @Test
    public void testCreateInvalidShamirShare() {
        boolean fail = true;

        try { // try x == 0
            new ShamirShare((byte) 0, new byte[]{1, 2, 3});
            fail = false;
        } catch (NullPointerException e) {
        }
        try { // try y == null
            new ShamirShare((byte) 7, null);
            fail = false;
        } catch (NullPointerException e) {
        }

        assertTrue(fail);
    }

    @Test
    public void testCreateInvalidReedSolomonShare() {
        boolean fail = true;

        try { // try x == 0
            new ReedSolomonShare((byte) 0, new byte[]{1, 2, 3}, 1);
            fail = false;
        } catch (NullPointerException e) {
        }
        try { // try y == null
            new ReedSolomonShare((byte) 7, null, 1);
            fail = false;
        } catch (NullPointerException e) {
        }
        try { // try originalLength < 0
            new ReedSolomonShare((byte) 7, new byte[]{1, 2, 3}, -17);
            fail = false;
        } catch (NullPointerException e) {
        }

        assertTrue(fail);
    }

    @Test
    public void testCreateInvalidKrawczykShare() {
        boolean fail = true;

        try { // try x == 0
            new KrawczykShare((byte) 0, new byte[]{1, 2, 3}, 1, new byte[]{1, 2, 3}, EncryptionAlgorithm.AES);
            fail = false;
        } catch (NullPointerException e) {
        }
        try { // try y == null
            new KrawczykShare((byte) 7, null, 1, new byte[]{1, 2, 3}, EncryptionAlgorithm.AES);
            fail = false;
        } catch (NullPointerException e) {
        }
        try { // try originalLength < 0
            new KrawczykShare((byte) 7, new byte[]{1, 2, 3}, -7, new byte[]{1, 2, 3}, EncryptionAlgorithm.AES);
            fail = false;
        } catch (NullPointerException e) {
        }
        try { // try keyY == null
            new KrawczykShare((byte) 7, new byte[]{1, 2, 3}, 0, null, EncryptionAlgorithm.AES);
            fail = false;
        } catch (NullPointerException e) {
        }
        try { // try alg == null
            new KrawczykShare((byte) 7, new byte[]{1, 2, 3}, 0, new byte[]{1, 2, 3}, null);
            fail = false;
        } catch (NullPointerException e) {
        }

        assertTrue(fail);
    }
}
