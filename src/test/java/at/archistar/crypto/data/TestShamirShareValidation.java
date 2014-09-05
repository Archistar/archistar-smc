package at.archistar.crypto.data;

import org.junit.Test;
import static org.fest.assertions.api.Assertions.*;

/**
 * test validity of Shamir shares
 */
public class TestShamirShareValidation {
    
    @Test(expected=InvalidParametersException.class)
    public void xMustNotBe0() throws InvalidParametersException {
        ShamirShare share = new ShamirShare((byte) 0, new byte[]{1, 2, 3});
        assertThat(share).isNotNull();
    }
    
    @Test(expected=InvalidParametersException.class)
    public void yMustNotBeNull() throws InvalidParametersException {
        ShamirShare share = new ShamirShare((byte) 7, null);
        assertThat(share).isNotNull();
    }
}
