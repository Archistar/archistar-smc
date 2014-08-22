package at.archistar.helper;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import at.archistar.crypto.data.Share;

/**
 * A helper-class for computing and validating MACs for {@link Share}s.
 * 
 * @author Elias Frantar
 * @version 2014-7-24
 */
public class ShareMacHelper implements MacHelper {
    
    private final Mac mac;
    
    /**
     * Constructor
     * 
     * @param algorithm the MAC algorithm to use (for example <i>SHA-256</i>)
     * @throws NoSuchAlgorithmException thrown if the given algorithm is not supported
     */
    public ShareMacHelper(String algorithm) throws NoSuchAlgorithmException {
        this.mac = Mac.getInstance(algorithm);
    }
    
    /**
     * @see #computeMAC(Share, byte[], int)
     * Uses algorithms default MAC-length.
     */
    @Override
    public byte[] computeMAC(Share share, byte[] key) throws InvalidKeyException {
        return computeMAC(share, key, mac.getMacLength());
    }
    /**
     * Computes the MAC of the specified length for the given share with the given key.
     * 
     * @param share the share to create the MAC for
     * @param key the key to use for computing the MAC
     * @param length the length of the returned tag
     * @return the message authentication code (tag or MAC) for this share
     * @throws InvalidKeyException thrown if an InvalidKeyException occurred
     */
    @Override
    public byte[] computeMAC(Share share, byte[] key, int length) throws InvalidKeyException {
        Key k = new SecretKeySpec(key, mac.getAlgorithm());
        mac.init(k);

        /* compute mac of serialized share */
        mac.update(share.serialize());

        return Arrays.copyOfRange(mac.doFinal(), 0, length); // return tag
    }
    
    /**
     * Verifies the given MAC.<br>
     * (recomputes the tag from share and key and compares it with the given tag)
     * 
     * @param share the share to verify the MAC for
     * @param tag the tag to verify
     * @param key the key to use for verification
     * @return true if verification was successful (the tags matched); false otherwise
     */
    @Override
    public boolean verifyMAC(Share share, byte[] tag, byte[] key) {
        boolean valid = false;
        
        try {
            byte[] newTag = computeMAC(share, key, tag.length); // compute tag for the given parameters
            valid = Arrays.equals(tag, newTag); // compare with original tag
        } catch (InvalidKeyException e) {}
        
        return valid;
    }
}
