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
public final class NTTShare extends BaseShare implements Comparable<NTTShare> {
    
    private final int shareCount;
    
    private final int originalLength;
    
    /**
     * Constructor
     * 
     * @param x the x-value (also identifier) of this share
     * @param y the y-values of this share
     * @throws InvalidParametersException if x == null or y == 0
     */
    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public NTTShare(byte x, byte[] y, int xCount, int originalLength) throws InvalidParametersException {
        super(x, y);
        if (!isValid()) {
            throw new InvalidParametersException();
        }
        this.shareCount = xCount;
        this.originalLength = originalLength;
    }
    
    public static NTTShare deserialize(DataInputStream in, int version, byte x) throws IOException, InvalidParametersException {
        int length = in.readInt();
        int tmpShareCount = in.readInt();
        int tmpOrigLength = in.readInt();
        byte[] tmpY = new byte[length];
        if (in.read(tmpY) == length) {
            return new NTTShare(x, tmpY, tmpShareCount, tmpOrigLength);
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
    
    @Override
    public void serializeBody(DataOutputStream os) throws IOException {
        os.writeInt(y.length);
        os.writeInt(shareCount);
        os.writeInt(originalLength);
        os.write(y);
    }

    @Override
    public int compareTo(NTTShare t) {
        if (t.getId() == getId() && Arrays.equals(t.getY(), getY())) {
            return 0;
        } else {
            return t.getId() - getId();
        }
    }
    
    @Override
    public boolean equals(Object o) {
        if (o instanceof NTTShare) {
            return compareTo((NTTShare)o) == 0;
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        assert false : "hashCode not designed";
        return 42;
    }

    public int getOriginalLength() {
        return this.originalLength;
    }

    public int getShareCount() {
        return this.shareCount;
    }
}
