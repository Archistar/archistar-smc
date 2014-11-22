package at.archistar.crypto.math;

import at.archistar.crypto.math.gf257.GF257;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.util.Arrays;

/**
 *
 * @author andy
 */
public class EncodingConverter {

    private int readPosition = 0;
    
    private int writePosition = 0;
    
    private byte[] data;
    
    private final GF gf;
    
    /**
     * initialize buffer with data, position is at start
     */
    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public EncodingConverter(byte[] data, GF gf) {
        this.data = data;
        this.gf = gf;
    }
    
    /**
     * initialize buffer with initial length of length, position is at start
     */
    public EncodingConverter(int length, GF gf) {
        this.data = new byte[length];
        this.gf = gf;
    }
    
    /**
     * @return encoded data
     */
    @SuppressFBWarnings("EI_EXPOSE_REP")
    public byte[] getEncodedData() {
        if (writePosition != data.length) {
            System.out.println("length difference: " + writePosition + " vs " + (data.length -1));
            assert(false);
            return Arrays.copyOf(data, writePosition);
        } else {
            return data;
        }
    }
    
    /**
     * @return next encoded entry at position, position is increased
     */
    public int readNext() {
        int tmp = data[readPosition++];
        
        /* -1 == 0xff, I pray for an unsigned byte data type */
        if (gf instanceof GF257 && tmp == -1) {
            return data[readPosition++] + 255;
        } else {
            /* always use 256 as this is the byte conversion, not
             * the conversion from GF(2^8) into whatever field we're
             * using.
             */
           return (tmp < 0) ? tmp + 256 : tmp;
        }
    }
    
    public boolean atEnd() {
        return (readPosition >= this.data.length);
    }
    
    /**
     * appends value to buffer
     */
    public void append(int value) {
        
        if (gf instanceof GF257 && value >= 0xff) {
            data = Arrays.copyOf(data, data.length +1);
            
            /* 0xff == -1 */
            data[writePosition++] = (byte)-1;
            value -= 255;
        }
        data[writePosition++] = (byte)(value & 0xff);
    }

    public int[] getDecodedData() {
        int[] tmp = new int[data.length];
        
        int pos = 0;
        while (!atEnd()) {
            tmp[pos++] = readNext();
        }
        
        return Arrays.copyOf(tmp, pos);
    }
}
