package at.archistar.crypto.data;

import org.junit.Test;
import static org.fest.assertions.api.Assertions.*;

import at.archistar.crypto.data.KrawczykShare.EncryptionAlgorithm;

/**
 * test validity of Krawcyk share-types.
 */
public class TestKrawcykShareValidation {
    
    private final static byte[] data = {1, 2, 3};
    private final static EncryptionAlgorithm alg = EncryptionAlgorithm.AES;
    
    @Test(expected=InvalidParametersException.class)
    public void xMustNotBe0() throws InvalidParametersException {
       Share share = new KrawczykShare((byte) 0, data, 1, data, alg);
       assertThat(share).isNotNull();
    }

    @Test(expected=InvalidParametersException.class)
    public void yMustNotBeNull() throws InvalidParametersException {
       Share share = new KrawczykShare((byte) 7, null, 1, data, alg);
       assertThat(share).isNotNull();
    }

    @Test(expected=InvalidParametersException.class)
    public void originalLengthMustBeGt0() throws InvalidParametersException {
       Share share = new KrawczykShare((byte) 7, data, -7, data, alg);
       assertThat(share).isNotNull();
    }

    @Test(expected=InvalidParametersException.class)
    public void algMustNotBeNull() throws InvalidParametersException {
       Share share = new KrawczykShare((byte) 7, data, 0, data, null);
       assertThat(share).isNotNull();
    }

    @Test(expected=InvalidParametersException.class)
    public void keyYMustNotBeNull() throws InvalidParametersException {
       Share share = new KrawczykShare((byte) 7, data, 0, null, alg);
       assertThat(share).isNotNull();
    }
}
