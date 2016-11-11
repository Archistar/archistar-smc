package at.archistar.crypto.data;

import org.junit.Test;

import static org.fest.assertions.api.Assertions.*;

/**
 * test share validations
 *
 * TODO: need to document these
 */
public class TestShareValidation {

    private static final byte[] data = {1, 2, 3};

    private static final byte[] key = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,
            21,22,23,24,25,26,27,28,29,30,31,32};

    @Test(expected = InvalidParametersException.class)
    public void xMustNotBe0() throws InvalidParametersException {
        Share share = new ShamirShare((byte) 0, data);
        assertThat(share).isNotNull();
    }

    @Test(expected = InvalidParametersException.class)
    public void yMustNotBeNull() throws InvalidParametersException {
        Share share = new ShamirShare((byte) 7, null);
        assertThat(share).isNotNull();
    }

    @Test
    public void allowValidShamirConstruction() throws InvalidParametersException {
        Share share = new ShamirShare((byte) 7, data);
        assertThat(share).isNotNull();
    }

    @Test
    public void allowValidRabinConstruction() throws InvalidParametersException {
        Share share = new RabinShare((byte) 7, data, 4);
        assertThat(share).isNotNull();
    }

    @Test
    public void allowValidKrawczykConstruction() throws InvalidParametersException {
        Share share = new KrawczykShare((byte) 7, data, 10, 1, key);
        assertThat(share).isNotNull();
    }


    @Test(expected = InvalidParametersException.class)
    public void KrawczykAlgMustNotBeNull() throws InvalidParametersException {
        Share share = new KrawczykShare((byte) 7, data, 1, 0, key);
        assertThat(share).isNotNull();
    }

    @Test(expected = InvalidParametersException.class)
    public void KrawczykKeyMustNotBeNull() throws InvalidParametersException {
        Share share = new KrawczykShare((byte) 7, data, 1, 1, null);
        assertThat(share).isNotNull();
    }

    @Test(expected = InvalidParametersException.class)
    public void KrawczykKeyMustBe32Bytes() throws InvalidParametersException {
        Share share = new KrawczykShare((byte) 7, data, 1, 1, new byte[]{1,2,3});
        assertThat(share).isNotNull();
    }
}
