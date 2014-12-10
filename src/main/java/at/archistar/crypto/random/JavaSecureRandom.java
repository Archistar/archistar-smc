package at.archistar.crypto.random;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * A wrapper class for the internal java PRNG
 */
public class JavaSecureRandom implements RandomSource {
    
    private static final String ALGORITHM = "SHA1PRNG";
    
    private final SecureRandom rng;
    
    private final byte[] bytes = new byte[1];
    
    /**
     * Constructor<br>
     * Immediately seeds the RNG with system-entropy. (may be a blocking call)
     */
    public JavaSecureRandom() { 
        try { 
            rng = SecureRandom.getInstance(ALGORITHM); 
        } catch (NoSuchAlgorithmException e) { // this should never happen
            throw new RuntimeException(e);
        }
        
        rng.nextBoolean(); // force the rng to seed itself
    }
    
    /**
      * this whole procedure is 2x as fast as nextInt(255) + 1
      * or three times as fast as rng.nextInt(8) & 0xff.
      * 
     * @return a new random byte
      */
    protected int generateByte() {
        do {
            rng.nextBytes(bytes);
        } while (bytes[0] == 0); // the random byte must not be 0
        
        return ((byte)(bytes[0] & 0xff) + 256) % 256;
    }
    
    /**
     * @return human readable representation of this random source
     */
    @Override
    public String toString() {
        return "JavaSecureRandom(" + ALGORITHM +")";
    }
    
    @Override
    public void fillBytes(byte[] toBeFilled) {
        for (int i = 0; i < toBeFilled.length; i++) {
            toBeFilled[i] = (byte)generateByte();
        }
    }
    
    @Override
    public void fillBytesAsInts(int[] toBeFilled) {
        for (int i = 0; i < toBeFilled.length; i++) {
            toBeFilled[i] = generateByte();
        }
    }
}
