package at.archistar.crypto.random;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;

/**
 * This is a counter-mode-cipher RNG outputting the result of running a symmetric cipher in counter-mode.
 */
public class CTRPRNG extends BaseRandomAlgorithm {
    
    private static final String ALGORITHM = "AES";
    
    private static final String PARAMS = "/ECB/NoPadding"; // we perform CTR by ourself
    
    private final Cipher cipher;
    
    private final byte[] state;
    
    /**
     * Constructor
     */
    public CTRPRNG() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
        cipher = Cipher.getInstance(ALGORITHM + PARAMS);
            
        KeyGenerator kgen = KeyGenerator.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, kgen.generateKey());
            
        state = kgen.generateKey().getEncoded(); // simply reuse the keygen to compute an IV
    }
    
    /**
     * Updates the cache with the encryption of the next block.
     */
    @Override
    protected void fillCache() {
        cache = cipher.update(state);
        counter = 0;
        
        incrementState();
    }
    
    /**
     * Increments the counter-block by one.
     */
    private void incrementState() {
        for (int i = state.length - 1; i >= 0; i--) { // take wrap-arounds into account
            if (++state[i] != 0) {
                break;
            }
        }
    }

    /**
     * @return human readable representation of this random source
     */
    @Override
    public String toString() {
        return "CTRPRNG(" + ALGORITHM + PARAMS +")";
    }
}
