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
    
    public void fillBytes(byte[] toBeFilled);

    public void fillBytesAsInts(int[] toBeFilled);
}
