package at.archistar.crypto.mac;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import at.archistar.crypto.data.Share;

/**
 * A helper-class for computing and validating MACs for {@link Share}s.
 */
public class JavaMacHelper implements MacHelper {
    
    private final Mac mac;
    
    /**
     * Constructor
     * 
     * @param algorithm the MAC algorithm to use (for example <i>SHA-256</i>)
     * @throws NoSuchAlgorithmException thrown if the given algorithm is not supported
     */
    public JavaMacHelper(String algorithm) throws NoSuchAlgorithmException {
        this.mac = Mac.getInstance(algorithm);
    }
    
    /**
     * Computes the MAC of the specified length for the given share with the given key.
     * 
     * @param key the key to use for computing the MAC
     * @return the message authentication code (tag or MAC) for this share
     * @throws InvalidKeyException thrown if an InvalidKeyException occurred
     */
    @Override
    public byte[] computeMAC(byte[] data, byte[] key) throws InvalidKeyException {
        Key k = new SecretKeySpec(key, mac.getAlgorithm());
        mac.init(k);

        /* compute mac of serialized share */
        mac.update(data);
        
        return mac.doFinal();
    }
    
    /**
     * Verifies the given MAC.<br>
     * (recomputes the tag from share and key and compares it with the given tag)
     * 
     * @param tag the tag to verify
     * @param key the key to use for verification
     * @return true if verification was successful (the tags matched); false otherwise
     */
    @Override
    public boolean verifyMAC(byte[] data, byte[] tag, byte[] key) {
        boolean valid = false;
        
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
        return "ShareMacHelper(" + this.mac.getAlgorithm()  + ")";
    }
}
