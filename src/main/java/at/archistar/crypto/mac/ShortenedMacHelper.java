/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package at.archistar.crypto.mac;

import at.archistar.crypto.informationchecking.CevallosUSRSS;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author andy
 */
public class ShortenedMacHelper implements MacHelper {
    
    private final Mac mac;
    
    private final int k;
    private final int e;
    
    /**
     * Constructor
     * 
     * @param algorithm the MAC algorithm to use (for example <i>SHA-256</i>)
     * @throws NoSuchAlgorithmException thrown if the given algorithm is not supported
     */
    public ShortenedMacHelper(String algorithm, int k, int e) throws NoSuchAlgorithmException {
        this.mac = Mac.getInstance(algorithm);
        this.k = k;
        this.e = e;
    }
    
    /**
     * @see #computeMAC(Share, byte[], int)
     * Uses algorithms default MAC-length.
     */
    @Override
    public byte[] computeMAC(byte[] data, byte[] key) throws InvalidKeyException {
        
        int length = CevallosUSRSS.computeTagLength(data.length*8, k, e);
        mac.init(new SecretKeySpec(key, mac.getAlgorithm()));

        /* compute mac of serialized share */
        mac.update(data);

        return Arrays.copyOfRange(mac.doFinal(), 0, length);
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
        return "ShortenedMacHelper(" + this.mac.getAlgorithm()  + ")";
    }
}
