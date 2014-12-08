package at.archistar.crypto.math;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

/**
 * custom version of ByteArrayOutputStream -- this is roughly 50% faster for
 * smaller sizes that the original ByteArrayOutputStream (end-performance wise).
 * 
 * This version does not do any conversion -- thus it can only be used for
 * operations within a GF <= 2^8
 */
public class StaticOutputEncoderConverter implements OutputEncoderConverter {
    
    private final byte buffer[];
    
    private int pos = 0;
 
    /**
     * initialize buffer with initial length of length, position is at start
     */
    public StaticOutputEncoderConverter(int initialLength) {
        this.buffer = new byte[initialLength];
    }
    
    /**
     * add data to the encoder's buffer
     * 
     * @param value to be added
     */
    @Override
    public void append(int value) {
        buffer[pos++] = (byte)value;
    }

    /**
     * add data to the encoder's buffer
     * 
     * @param values array of values to be added
     * @param offset from where to start to take the values from
     * @param count how many values to take
     */
    @Override
    public void append(int[] values, int offset, int count) {
        
        for (int i = 0; i < count; i++) {
            buffer[pos++] = (byte)values[offset+i];
        }
    }

    /**
     * @return encoded data
     */
    @SuppressFBWarnings("EI_EXPOSE_REP")
    @Override
    public byte[] getEncodedData() {
        return buffer;
    }
}
