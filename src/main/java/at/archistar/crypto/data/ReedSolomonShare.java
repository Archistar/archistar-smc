package at.archistar.crypto.data;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

/**
 * Represents a share for {@link RabinIDS}.
 */
public final class ReedSolomonShare extends BaseShare {
    private final int originalLength;
    
    /**
     * Constructor
     * 
     * @param x the x-value (also identifier) of this share
     * @param y the y-values of this share
     * @param originalLength the original length of the shared data
     * @throws NullPointerException if validation failed ({@link #validateShare()})
     */
    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public ReedSolomonShare(byte x, byte[] y, int originalLength) {
        
        super(x, y);
        this.originalLength = originalLength;
        
        if (!isValid()) {
            throw new NullPointerException();
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
    public static ReedSolomonShare deserialize(DataInputStream in, int version, byte x) throws IOException {
        
        int originalLength = in.readInt();
        int count = in.readInt();        
        byte[] y = new byte[count];
        assert in.read(y) == count;
        return new ReedSolomonShare(x, y, originalLength);
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
}
