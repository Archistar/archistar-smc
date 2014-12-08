package at.archistar.crypto.math;

/**
 * Converts data from int to byte. This is ie. needed for all operations within
 * GF257 as the resulting values do not fit within a single byte.
 */
public interface OutputEncoderConverter {
    
    /**
     * add data to the encoder's buffer
     * 
     * @param value to be added
     */
    void append(int value);

    /**
     * add data to the encoder's buffer
     * 
     * @param values array of values to be added
     * @param offset from where to start to take the values from
     * @param count how many values to take
     */
    void append(int[] values, int offset, int count);
    
    /**
     * @return encoded data
     */
    byte[] getEncodedData();
}
