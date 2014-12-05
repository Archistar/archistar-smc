package at.archistar.crypto.random;

import java.util.Arrays;

/**
 * Fake Random numbers for test cases -- this allows us to easily compare
 * results within test cases
 */
public class FakeRandomSource implements RandomSource {

    @Override
    public void fillBytes(byte[] toBeFilled) {
        Arrays.fill(toBeFilled, (byte)4);
    }
    
    @Override
    public void fillBytesAsInts(int[] toBeFilled) {
        Arrays.fill(toBeFilled, (byte)4);
    }
    
    /**
     * @return human readable representation of this random source
     */
    @Override
    public String toString() {
        return "FakeRandomSource()";
    }
}
