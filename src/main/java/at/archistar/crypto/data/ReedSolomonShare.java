package at.archistar.crypto.data;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 * Represents a share for {@link RabinIDS}.
 */
public final class ReedSolomonShare extends BaseShare implements Comparable<ReedSolomonShare> {
    
    private final int originalLength;
    
    /**
     * Constructor
     * 
     * @param x the x-value (also identifier) of this share
     * @param y the y-values of this share
     * @param originalLength the original length of the shared data
     * @throws InvalidParametersException if validation failed ({@link #validateShare()})
     */
    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public ReedSolomonShare(byte x, byte[] y, int originalLength) throws InvalidParametersException {
        
        super(x, y);
        this.originalLength = originalLength;
        
        if (!isValid()) {
            throw new InvalidParametersException();
        }
    }
    
    /**
     * De-serializes a serialized ReedSolomonShare.
     * 
     * @param in the serialized data (must be a valid serialized ReedSolomonShare)
     * @param version the version (extracted from serialized data header)
     * @param x the key/id (extracted from serialized data header)
     * @returns the newly created share
     */
    public static ReedSolomonShare deserialize(DataInputStream in, int version, byte x) throws IOException, InvalidParametersException {
        
        int originalLength = in.readInt();
        int count = in.readInt();        
        byte[] y = new byte[count];
        if (in.read(y) == count) {
            return new ReedSolomonShare(x, y, originalLength);
        } else {
            throw new InvalidParametersException("data length inconsistent");
        }
    }

    @Override
    public Algorithm getAlgorithm() {
        return Algorithm.REED_SOLOMON;
    }

    @Override
    public void serializeBody(DataOutputStream os) throws IOException {
        os.writeInt(originalLength);
        os.writeInt(y.length);
        os.write(y);
    }
    
    /**
     * Validates this share by checking if:
     * <ul>
     *  <li>x is not 0
     *  <li>y is not null
     *  <li>originalLength is larger than 0
     * </ul>
     * @return true if share is valid
     */
    @Override
    public boolean isValid() {
        return !(x == 0 || y == null || originalLength <= 0);
    }
    
    public int getOriginalLength() {
        return originalLength;
    }

    @Override
    public int compareTo(ReedSolomonShare t) {
        if (t.getId() == getId() && Arrays.equals(t.getY(), getY()) && t.getOriginalLength() == getOriginalLength()) {
            return 0;
        } else {
            return t.getId() - getId();
        }
    }
    
    @Override
    public boolean equals(Object o) {
        if (o instanceof ReedSolomonShare) {
            return compareTo((ReedSolomonShare)o) == 0;
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        assert false : "hashCode not designed";
        return 42;
    }

    public void setNewSize(int i) {
        this.y = Arrays.copyOf(this.y, i);
    }
}
