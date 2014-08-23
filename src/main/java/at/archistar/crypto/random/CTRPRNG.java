package at.archistar.crypto.random;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import java.security.GeneralSecurityException;

import at.archistar.crypto.exceptions.ImpossibleException;
import at.archistar.crypto.data.ByteUtils;

/**
 * This is a counter-mode-cipher RNG outputting the result of running a symmetric cipher in counter-mode.
 * 
 * @author Elias Frantar
 * @version 2014-7-18
 */
public class CTRPRNG implements RandomSource {
    private static final String ALGORITHM = "AES";
    private static final String PARAMS = "/ECB/NoPadding"; // we perform CTR by ourself
    
    private Cipher cipher;
    
    private byte[] state;
    
    private byte[] cache; 
    private int counter;
    
    /**
     * Constructor
     */
    public CTRPRNG() {
        try {
            cipher = Cipher.getInstance(ALGORITHM + PARAMS);
            
            KeyGenerator kgen = KeyGenerator.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, kgen.generateKey());
            
            state = kgen.generateKey().getEncoded(); // simply reuse the keygen to compute an IV
            
            counter = 0;
            
            fillCache();
        } catch (GeneralSecurityException e) { // should never happen
            throw new ImpossibleException(e);
        }
    }
    
    /**
     * Updates the cache with the encryption of the next block.
     */
    private void fillCache() {
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

    private int generateByte() {
        byte b;
        do {
            if (counter > cache.length - 1) {
                fillCache();
            }
        } while ((b = cache[counter++]) == 0); // result must not be 0
        
        return ByteUtils.toUnsignedByte(b);
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
