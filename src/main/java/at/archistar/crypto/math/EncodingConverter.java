package at.archistar.crypto.math;

import at.archistar.crypto.math.gf257.GF257;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.util.Arrays;

/**
 * This input data converter automatically checks if the input data is within
 * GF256 or GF257 and converts the byte values into corresponding integer
 * values
 */
public class EncodingConverter {

    private int readPosition = 0;
    
    private final byte[] data;
    
    private final GF gf;
    
    /**
     * initialize buffer with data, position is at start
     * @param data
     * @param gf
     */
    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public EncodingConverter(byte[] data, GF gf) {
        this.data = data;
        this.gf = gf;
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
    
    /**
     * @return true if the end of the input buffer was reached
     */
    public boolean atEnd() {
        return (readPosition >= this.data.length);
    }
    
    /**
     * @return the whole input buffer converted into int[]
     */
    public int[] getDecodedData() {
        int[] tmp = new int[data.length];
        
        int pos = 0;
        while (!atEnd()) {
            tmp[pos++] = readNext();
        }
        
        return Arrays.copyOf(tmp, pos);
    }
}
