package at.archistar.crypto.random;

/**
 * This is the base interface for Random-Number-Generators used in this library.<br>
 * It allows easy exchange of RNGs. 
 */
public interface RandomSource {
    
    public void fillBytes(byte[] toBeFilled);

    public void fillBytesAsInts(int[] toBeFilled);
}
