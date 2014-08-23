/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package at.archistar.crypto.mac;

import at.archistar.crypto.CevallosUSRSS;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 *
 * @author andy
 */
public class BCShortenedMacHelper implements MacHelper {
    
    private final MacHelper mac;
    
    private final int k;
    private final int e;
    
    /**
     * Constructor
     * 
     * @param mac the MAC algorithm to use (for example <i>SHA-256</i>)
     * @throws NoSuchAlgorithmException thrown if the given algorithm is not supported
     */
    public BCShortenedMacHelper(MacHelper mac, int k, int e) throws NoSuchAlgorithmException {
        this.mac = mac;
        this.k = k;
        this.e = e;
    }
    
    /**
     * @see #computeMAC(Share, byte[], int)
     * Uses algorithms default MAC-length.
     */
    @Override
    public byte[] computeMAC(byte[] data, byte[] key) throws InvalidKeyException {
        
        byte[] result = mac.computeMAC(data, key);
        int length = CevallosUSRSS.computeTagLength(data.length*8, k, e);
        return Arrays.copyOfRange(result, 0, length);
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
        
        try {
            byte[] newTag = computeMAC(data, key); // compute tag for the given parameters
            valid = Arrays.equals(tag, newTag); // compare with original tag
        } catch (InvalidKeyException e) {}
        
        return valid;
    }

    @Override
    public int keySize() {
        return this.mac.keySize();
    }
    
    @Override
    public String toString() {
        return "BCShortenedMacHelper(" + this.mac  + ")";
    }
}
