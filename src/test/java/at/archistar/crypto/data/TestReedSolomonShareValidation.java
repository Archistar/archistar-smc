package at.archistar.crypto.data;

import org.junit.Test;
import static org.fest.assertions.api.Assertions.*;


/**
 * test validation of ReedSolomon Shares
 */
public class TestReedSolomonShareValidation {
    
    private static final byte[] data = {1, 2, 3};

    @Test(expected=InvalidParametersException.class)
    public void xMustNotBe0() throws InvalidParametersException {
        Share share = new ReedSolomonShare((byte) 0, data, 1);
        assertThat(share).isNotNull();
    }
    
    @Test(expected=InvalidParametersException.class)
    public void yMustNotBeNull() throws InvalidParametersException {
        Share share = new ReedSolomonShare((byte) 7, null, 1);
        assertThat(share).isNotNull();
    }
    
    @Test(expected=InvalidParametersException.class)
    public void originalLengthMustBeGt0() throws InvalidParametersException {
        Share share = new ReedSolomonShare((byte) 7, data, -17);
        assertThat(share).isNotNull();
    }
}
