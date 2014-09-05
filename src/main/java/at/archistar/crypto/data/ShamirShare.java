package at.archistar.crypto.data;

import at.archistar.crypto.secretsharing.ShamirPSS;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;


/**
 * Represents a share for {@link ShamirPSS}.
 */
public final class ShamirShare extends BaseShare implements Comparable<ShamirShare> {
    /**
     * Constructor
     * 
     * @param x the x-value (also identifier) of this share
     * @param y the y-values of this share
     * @throws InvalidParametersException if x == null or y == 0
     */
    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public ShamirShare(byte x, byte[] y) throws InvalidParametersException {
        super(x, y);
        if (!isValid()) {
            throw new InvalidParametersException();
        }
    }
    
    public static ShamirShare deserialize(DataInputStream in, int version, byte x) throws IOException, InvalidParametersException {
        int length = in.readInt();
        byte[] tmpY = new byte[length];
        if (in.read(tmpY) == length) {
            return new ShamirShare(x, tmpY);
        } else {
            throw new InvalidParametersException("not enough data during deserialization");
        }
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

    @Override
    public int compareTo(ShamirShare t) {
        if (t.getId() == getId() && Arrays.equals(t.getY(), getY())) {
            return 0;
        } else {
            return t.getId() - getId();
        }
    }
    
    @Override
    public boolean equals(Object o) {
        if (o instanceof ShamirShare) {
            return compareTo((ShamirShare)o) == 0;
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        assert false : "hashCode not designed";
        return 42;
    }
}
