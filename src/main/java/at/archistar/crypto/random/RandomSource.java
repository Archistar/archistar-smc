package at.archistar.crypto.random;

/**
 * This is the base interface for Random-Number-Generators used in this library.<br>
 * It allows easy exchange of RNGs. 
 *
 * @author Elias Frantar <i>(added documentation)</i>
 * @author Andreas Happe <andreashappe@snikt.net>
 * @version 2014-7-18
 */
public interface RandomSource {

    /**
     * Generates a new random byte in range 1 - 255. (as an integer)
     * @return a random byte excluding 0
     */
    public int generateByte(); // return int because there are no unsigned bytes in java
    
    public void fillBytes(byte[] toBeFilled);

    public void fillBytesAsInts(int[] toBeFilled);
}
