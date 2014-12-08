package at.archistar.crypto.mac;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * This is just part of a proof-of-concept of a key-shortener used for an
 * accurate implementation of the Cevallos-Scheme
 */
public class BCShortenedMacHelper implements MacHelper {
    
    private final MacHelper mac;
    
    private final int keylength;
    
    /**
     * Constructor
     * 
     * @param mac the MAC algorithm to use (for example <i>SHA-256</i>)
     * @param keylength the actually needed (input and output) keylength
     * @throws NoSuchAlgorithmException thrown if the given algorithm is not supported
     */
    public BCShortenedMacHelper(MacHelper mac, int keylength) throws NoSuchAlgorithmException {
        this.mac = mac;
        this.keylength = keylength;
    }
    
    @Override
    public byte[] computeMAC(byte[] data, byte[] key) throws InvalidKeyException {
        
        /* create the short key, padded with 0s */
        byte[] shortKey = new byte[this.mac.keySize()];
        Arrays.copyOfRange(key, 0, keylength);
        
        byte[] result = mac.computeMAC(data, shortKey);

        /* return only keys of a given length */
        return Arrays.copyOfRange(result, 0, keylength);
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
        
        byte[] shortKey = new byte[this.mac.keySize()];
        Arrays.copyOfRange(key, 0, keylength);        
        
        try {
            byte[] newTag = computeMAC(data, shortKey); // compute tag for the given parameters
            byte[] shortTag = Arrays.copyOfRange(newTag, 0, keylength);
            valid = Arrays.equals(tag, shortTag); // compare with original tag
        } catch (InvalidKeyException e) {
            throw new RuntimeException("this should not happen");
        }
        
        return valid;
    }

    /**
     * @return needed keylength (in byte) for this algorithm
     */
    @Override
    public int keySize() {
        return this.keylength;
    }

    /**
     * @return human-readable description for this algorithm
     */
    @Override
    public String toString() {
        return "BCShortenedMacHelper(" + this.mac  + ")";
    }
}
