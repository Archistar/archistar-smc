package at.archistar.crypto.math;

/**
 *
 * @author andy
 */
public interface OutputEncoderConverter {
    void append(int value);
        
    void append(int[] values, int offset, int count);
        
    byte[] getEncodedData();
}
