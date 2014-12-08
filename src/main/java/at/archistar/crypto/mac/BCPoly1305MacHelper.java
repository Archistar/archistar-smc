package at.archistar.crypto.mac;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.generators.Poly1305KeyGenerator;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * Use bouncy castle's poly1305 engine for creating macs
 */
public class BCPoly1305MacHelper implements MacHelper {
    
    private final Mac mac;
    
    /**
     * Constructor
     * 
     * @throws NoSuchAlgorithmException thrown if the given algorithm is not supported
     */
    public BCPoly1305MacHelper() throws NoSuchAlgorithmException {
        this.mac = new Poly1305();
    }
    
    /**
     * Computes the MAC of the specified length for the given share with the given key.
     * 
     * @param data the data to create the MAC for
     * @param key the key to use for computing the MAC
     * @return the message authentication code (tag or MAC) for this share
     * @throws InvalidKeyException thrown if an InvalidKeyException occurred
     */
    @Override
    public byte[] computeMAC(byte[] data, byte[] key) throws InvalidKeyException {
        
        byte[] result = new byte[mac.getMacSize()];
        
        Poly1305KeyGenerator.clamp(key);
        
        mac.init(new KeyParameter(key));
        mac.update(data, 0, data.length);
        mac.doFinal(result, 0);
        return result;
    }
    
    /**
     * Verifies the given MAC.<br>
     * (recomputes the tag from share and key and compares it with the given tag)
     * 
     * @param data the data to verify the MAC for
     * @param tag the tag to verify
     * @param key the key to use for verification
     * @return true if verification was successful (the tags matched); false otherwise
     */
    @Override
    public boolean verifyMAC(byte[] data, byte[] tag, byte[] key) {
        boolean valid = false;
        
        Poly1305KeyGenerator.clamp(key);
        
        try {
            byte[] newTag = computeMAC(data, key); // compute tag for the given parameters
            valid = Arrays.equals(tag, newTag); // compare with original tag
        } catch (InvalidKeyException e) {}
        
        return valid;
    }

    @Override
    public int keySize() {
        return 32;
    }
    
    @Override
    public String toString() {
        return "Poly1305()";
    }
}
