package at.archistar.crypto.math;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

/**
 * custom version of ByteArrayOutputStream -- this is roughly 50% faster for
 * smaller sizes that the original ByteArrayOutputStream (end-performance wise)
 * 
 * @author andy
 */
public class StaticOutputEncoderConverter implements OutputEncoderConverter {
    
    //private final ByteArrayOutputStream buffer;
    
    private final byte buffer[];
    
    private int pos = 0;
 
    /**
     * initialize buffer with initial length of length, position is at start
     */
    public StaticOutputEncoderConverter(int initialLength) {
        this.buffer = new byte[initialLength];
    }
    
    @Override
    public void append(int value) {
        buffer[pos++] = (byte)value;
    }
    
    @Override
    public void append(int[] values, int offset, int count) {
        
        for (int i = 0; i < count; i++) {
            buffer[pos++] = (byte)values[offset+i];
        }
    }
    
    @SuppressFBWarnings("EI_EXPOSE_REP")
    @Override
    public byte[] getEncodedData() {
        return buffer;
    }
}
