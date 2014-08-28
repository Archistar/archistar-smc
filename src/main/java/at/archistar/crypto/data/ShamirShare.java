package at.archistar.crypto.data;

import at.archistar.crypto.secretsharing.ShamirPSS;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;


/**
 * Represents a share for {@link ShamirPSS}.
 */
public final class ShamirShare extends BaseShare { // objects of this class should be immutable
    /**
     * Constructor
     * 
     * @param x the x-value (also identifier) of this share
     * @param y the y-values of this share
     * @throws NullPointerException if validation failed ({@link #validateShare()})
     */
    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public ShamirShare(byte x, byte[] y) {
        super(x, y);
        if (!isValid()) {
            throw new NullPointerException();
        }
    }
    
    public static ShamirShare deserialize(DataInputStream in, int version, byte x) throws IOException {
        int length = in.readInt();
        byte[] tmpY = new byte[length];
        assert in.read(tmpY) == length;
        return new ShamirShare(x, tmpY);
    }
    
    @Override
    public Algorithm getAlgorithm() {
        return Algorithm.SHAMIR;
    }

    /**
     * Validates this share by checking if:
     * <ul>
     *  <li>x is not 0
     *  <li>y is not null
     * </ul>
     * @throws NullPointerException if any of the above conditions is violated
     */
    @Override
    public  boolean isValid() {
        return  !(x == 0 || y == null); // x cannot be < 0 because it is an unsigned byte
    }
    
        /**
     * Extracts all i<sup>th</sup> y-values from the given Share[].
     * 
     * @param shares the shares to extract the y-values from
     * @param i the index of the y-value to extract from each share
     * @return an array with all i<sup>th</sup> y-values from the given shares (in same order as the given Share[])
     */
    public static int[] extractYVals(ShamirShare[] shares, int i) {
        int[] y = new int[shares.length];
        
        for (int j = 0; j < y.length; j++) {
            y[j] = ByteUtils.toUnsignedByte(shares[j].getY()[i]);
        }
        
        return y;
    }

    @Override
    public void serializeBody(DataOutputStream os) throws IOException {
        os.writeInt(y.length);
        os.write(y);
    }
}
