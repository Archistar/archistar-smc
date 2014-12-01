package at.archistar.crypto.math;

import at.archistar.crypto.math.gf257.GF257;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.util.Arrays;

/**
 * custom version of ByteArrayOutputStream -- this is roughly 50% faster for
 * smaller sizes that the original ByteArrayOutputStream (end-performance wise)
 * 
 * @author andy
 */
public class OutputEncoderConverter {
    
    //private final ByteArrayOutputStream buffer;
    
    private byte buffer[];
    
    private final GF gf;
    
    private int pos = 0;
 
    /**
     * initialize buffer with initial length of length, position is at start
     */
    public OutputEncoderConverter(int initialLength, GF gf) {
        
        if (gf instanceof GF257) {
            initialLength = (int)(initialLength * 1.1);
        }
        //this.buffer = new ByteArrayOutputStream(initialLength);
        this.buffer = new byte[initialLength];
        this.gf = gf;
    }
    
    public void append(int value) {
        if (gf instanceof GF257 && value >= 0xff) {
            if (pos == buffer.length || (pos -1) == buffer.length) {
                buffer = Arrays.copyOf(buffer, (int)(pos + pos*0.1));
            }

            /* 0xff == -1 */
            buffer[pos++] = (byte) -1;
            value -= 255;
        }
        
        if (pos == buffer.length || (pos -1) == buffer.length) {
            buffer = Arrays.copyOf(buffer, (int)(pos + pos*0.1));
        }
        
        buffer[pos++] = (byte)value;
    }
    
    public void append(int[] values, int offset, int count) {
        for (int i = 0; i < count; i++) {
            int value = values[offset + i];
            
            if (gf instanceof GF257 && value >= 0xff) {
                if (pos == buffer.length || (pos -1) == buffer.length) {
                    buffer = Arrays.copyOf(buffer, (int)(pos + pos*0.1));
                }

                /* 0xff == -1 */
                buffer[pos++] = (byte) -1;
                value -= 255;
            }
        
            if (pos == buffer.length || (pos -1) == buffer.length) {
                buffer = Arrays.copyOf(buffer, (int)(pos + pos*0.1));
            }
        
            buffer[pos++] = (byte)value;
        }
    }
    
    @SuppressFBWarnings("EI_EXPOSE_REP")
    public byte[] getEncodedData() {
        if (pos != buffer.length) {
            return Arrays.copyOf(buffer, pos);
        } else {
            return buffer;
        }
    }
}
