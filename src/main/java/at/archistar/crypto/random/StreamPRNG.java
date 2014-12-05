package at.archistar.crypto.random;

import java.security.Security;
import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * This is a stream-cipher RNG outputting the key-stream of a stream-cipher as random numbers.<br>
 */
public class StreamPRNG implements RandomSource {
    
    /** identifier for the <i>Salsa20</i> algorithm */
    public static final String SALSA20 = "Salsa20";
    
    /** identifier for the <i>HC128</i> algorithm */
    public static final String HC128 = "HC128";
    
    private static final byte[] dummy = new byte[16]; // we are only interested in the key-stream (so fill with 0s)
    
    static {
        Security.addProvider(new BouncyCastleProvider()); // we need to add the "bouncycastle"-provider only once
    }
    
    private final Cipher cipher;
    
    private byte[] cache;
    
    private int counter;
    
    /**
     * Constructor
     * @param algorithm the stream-cipher algorithm to use (do only pass constants of this class)
     * @throws GeneralSecurityException thrown if initialization of the RNG failed
     */
    public StreamPRNG(String algorithm) throws GeneralSecurityException {
        cipher = Cipher.getInstance(algorithm, "BC"); // we want implementations from bouncycastle
                
        KeyGenerator kgen = KeyGenerator.getInstance(algorithm, "BC");
        cipher.init(Cipher.ENCRYPT_MODE, kgen.generateKey());
                
        fillCache();
    }
    
    /**
     * Updates the cache with the next iteration of output from the stream-cipher.
     */
    private void fillCache() {
        cache = cipher.update(dummy); // fill the cache with the keystream
        counter = 0;
    }

    private int generateByte() {
        byte b;
        do {
            if (counter > cache.length - 1) {
                fillCache();
            }
        } while ((b = cache[counter++]) == 0); // result must not be 0
        
        return b & 0xff;
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
    
    /**
     * @return human readable representation of this random source
     */
    @Override
    public String toString() {
        return "StreamPRNG(" + cipher.getAlgorithm() + ")";
    }
}
