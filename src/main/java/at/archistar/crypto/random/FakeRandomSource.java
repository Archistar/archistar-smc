package at.archistar.crypto.random;

/**
 * Fake Random numbers for test cases -- this allows us to easily compare
 * results within test cases
 *
 * @author Andreas Happe <andreashappe@snikt.net>
 */
public class FakeRandomSource implements RandomSource {

    @Override
    public void fillBytes(byte[] toBeFilled) {
        for (int i = 0; i < toBeFilled.length; i++) {
            toBeFilled[i] = (byte)4;
        }
    }
    
    @Override
    public void fillBytesAsInts(int[] toBeFilled) {
        for (int i = 0; i < toBeFilled.length; i++) {
            toBeFilled[i] = 4;
        }
    }
}
