package at.archistar.crypto.random;

/**
 * This is the base interface for Random-Number-Generators used in this library.<br>
 * It allows easy exchange of RNGs. 
 */
public interface RandomSource {
    
    /**
     * fill an (byte) array with random data
     * @param toBeFilled the array to be filled
     */
    public void fillBytes(byte[] toBeFilled);

    /**
     * fill an (integer) array with random data
     * @param toBeFilled the array to be filled
     */
    public void fillBytesAsInts(int[] toBeFilled);
}
