package at.archistar.crypto.mac;

import at.archistar.crypto.math.gf256.GF256;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.fest.assertions.api.Assertions.assertThat;

import org.junit.Test;

public class PolyHashTest {

    @Test
    public void testHashVerifyCycle() throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] data = new byte[1024];

        /* let's create a 64 bit hash */
        byte[] key = new byte[64 / 8 * 2];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) i;
        }

        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) i;
        }

        MacHelper mac = new PolyHash(64 / 8, new GF256());
        byte[] hash = mac.computeMAC(data, key);
        assertThat(hash.length).isEqualTo(8);
        assertThat(mac.verifyMAC(data, hash, key)).isEqualTo(true);
    }
}
