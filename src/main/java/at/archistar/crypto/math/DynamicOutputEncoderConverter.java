package at.archistar.crypto.math;

import at.archistar.crypto.math.gf256.GF256;
import at.archistar.crypto.math.gf257.GF257;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.util.Arrays;

/**
 * custom version of ByteArrayOutputStream -- this is roughly 50% faster for
 * smaller sizes that the original ByteArrayOutputStream (end-performance wise)
 */
public class DynamicOutputEncoderConverter implements OutputEncoderConverter {
    
    //private final ByteArrayOutputStream buffer;
    
    private byte buffer[];
    
    private final GF gf;
    
    private int pos = 0;
 
    /**
     * initialize buffer with initial length of length, position is at start
     */
    public DynamicOutputEncoderConverter(int initialLength, GF gf) {
        
        if (gf instanceof GF257) {
            initialLength = (int)(initialLength * 1.1);
        }
        //this.buffer = new ByteArrayOutputStream(initialLength);
        this.buffer = new byte[initialLength];
        this.gf = gf;
    }
    
    /**
     * add data to the encoder's buffer
     * 
     * @param value to be added
     */
    @Override
    public void append(int value) {
        
        if (gf instanceof GF257 && (pos == buffer.length || (pos -1) == buffer.length)) {
            buffer = Arrays.copyOf(buffer, (int)(pos + pos*0.01));
        }
        
        if (value < 0xff) {
            buffer[pos++] = (byte)value;
        } else if (gf instanceof GF256) {
            buffer[pos++] = (byte)value;
        } else if (gf instanceof GF257) {
            buffer[pos++] = (byte) -1;
            buffer[pos++] = (byte)(value-255);
        }
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
            int value = values[offset + i];
            
            if (gf instanceof GF257 && (pos == buffer.length || (pos -1) == buffer.length)) {
                buffer = Arrays.copyOf(buffer, (int)(pos + pos*0.01));
            }
        
            if (value < 0xff) {
                buffer[pos++] = (byte)value;
            } else if (gf instanceof GF256) {
                buffer[pos++] = (byte)value;
            } else if (gf instanceof GF257) {
                buffer[pos++] = (byte) -1;
                buffer[pos++] = (byte)(value-255);
            }
        }
    }
    
    /**
     * @return encoded data
     */
    @SuppressFBWarnings("EI_EXPOSE_REP")
    @Override
    public byte[] getEncodedData() {
        if (pos != buffer.length) {
            return Arrays.copyOf(buffer, pos);
        } else {
            return buffer;
        }
    }
}
