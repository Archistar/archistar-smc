package at.archistar.crypto.random;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import at.archistar.crypto.exceptions.ImpossibleException;

/**
 * A wrapper class for the internal java PRNG
 * 
 * NOTE: Since this PRNG is secure it is used as default generator for all SecretSharing algorithms.
 */
public class JavaSecureRandom implements RandomSource {
    
    private static final String ALGORITHM = "SHA1PRNG";
    
    private SecureRandom rng;
    
    /**
     * Constructor<br>
     * Immediately seeds the RNG with system-entropy. (may be a blocking call)
     */
    public JavaSecureRandom() { 
        try { 
            rng = SecureRandom.getInstance(ALGORITHM); 
        } catch (NoSuchAlgorithmException e) { // this should never happen
            throw new ImpossibleException(e);
        }
        
        rng.nextBoolean(); // force the rng to seed itself
    }
    
    private int generateByte() {
        /* this whole procedure is 2x as fast as nextInt(255) + 1 */
        /* or three times as fast as rng.nextInt(8) & 0xff; */
        byte[] bytes = new byte[1];
        
        do {
            rng.nextBytes(bytes);
        } while (bytes[0] == 0); // the random byte must not be 0
        
        return ((byte)(bytes[0] & 0xff) + 256) % 256;
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
