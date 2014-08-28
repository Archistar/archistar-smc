package at.archistar.crypto.mac;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * 
 * @author andy
 */
public class BCMacHelper implements MacHelper {
    
    private final Mac mac;
    
    /** TODO: cannot I gather this from the BC API? */
    private final int keySize;
    
    /**
     * Constructor
     * 
     * @param mac the MAC algorithm to use (for example <i>SHA-256</i>)
     * @throws NoSuchAlgorithmException thrown if the given algorithm is not supported
     */
    public BCMacHelper(Mac mac, int keySize) throws NoSuchAlgorithmException {
        this.mac = mac;
        this.keySize = keySize;
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
        
        byte[] result = new byte[keySize];
        
        mac.init(new KeyParameter(key));
        mac.update(data, 0, data.length);
        mac.doFinal(result, 0);
        return result;
    }
    
    /**
     * Verifies the given MAC.<br>
     * (recomputes the tag from share and key and compares it with the given tag)
     * 
     * @param data the share to verify the MAC for
     * @param tag the tag to verify
     * @param key the key to use for verification
     * @return true if verification was successful (the tags matched); false otherwise
     */
    @Override
    public boolean verifyMAC(byte[] data, byte[] tag, byte[] key) {
        try {
            byte[] newTag = computeMAC(data, key);
            return Arrays.equals(tag, newTag);
        } catch (InvalidKeyException e) {
            return false;
        }
    }

    @Override
    public int keySize() {
        return this.keySize;
    }
    
    @Override
    public String toString() {
        return "BCMacHelper(" + this.mac.getAlgorithmName() + ")";
    }
}
