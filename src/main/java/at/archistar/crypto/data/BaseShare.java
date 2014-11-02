package at.archistar.crypto.data;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

/**
 * @author andy
 */
public abstract class BaseShare extends SerializableShare {
    
    protected final byte x;
    protected byte[] y;
    
    
    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public BaseShare(byte x, byte[] y) {
        this.x = x;
        this.y = y;
    }

        /**
     * Extracts all x-values from the given Share[].
     * @param shares the shares to extract the x-values from
     * @return an array with all x-values from the given shares (in same order as the given Share[])
     */
    public static int[] extractXVals(Share[] shares) {
        int[] x = new int[shares.length];
        
        for (int i = 0; i < x.length; i++) {
            x[i] = shares[i].getId();
        }
        
        return x;
    }
    
        /* Getters */
    @SuppressFBWarnings("EI_EXPOSE_REP")
    public byte[] getY() {
        return y;
    }
    
    @Override
    public int getId() {
        return ByteUtils.toUnsignedByte(x);
    }
}
