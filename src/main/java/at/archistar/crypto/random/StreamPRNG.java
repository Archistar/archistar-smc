package at.archistar.crypto.random;

import java.security.Security;
import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * This is a stream-cipher RNG outputting the key-stream of a stream-cipher as random numbers.<br>
 */
public class StreamPRNG extends BaseRandomAlgorithm {
    
    /** identifier for the <i>Salsa20</i> algorithm */
    public static final String SALSA20 = "Salsa20";
    
    /** identifier for the <i>HC128</i> algorithm */
    public static final String HC128 = "HC128";
    
    private static final byte[] DUMMY = new byte[16]; // we are only interested in the key-stream (so fill with 0s)
    
    static {
        Security.addProvider(new BouncyCastleProvider()); // we need to add the "bouncycastle"-provider only once
    }
    
    private final Cipher cipher;
    
    /**
     * Constructor
     * @param algorithm the stream-cipher algorithm to use (do only pass constants of this class)
     * @throws GeneralSecurityException thrown if initialization of the RNG failed
     */
    public StreamPRNG(String algorithm) throws GeneralSecurityException {
        cipher = Cipher.getInstance(algorithm, "BC"); // we want implementations from bouncycastle
                
        KeyGenerator kgen = KeyGenerator.getInstance(algorithm, "BC");
        cipher.init(Cipher.ENCRYPT_MODE, kgen.generateKey());
    }
    
    /**
     * Updates the cache with the next iteration of output from the stream-cipher.
     */
    @Override
    protected void fillCache() {
        cache = cipher.update(DUMMY); // fill the cache with the keystream
        counter = 0;
    }
    
    /**
     * @return human readable representation of this random source
     */
    @Override
    public String toString() {
        return "StreamPRNG(" + cipher.getAlgorithm() + ")";
    }
}
