package at.archistar.crypto.mac;

import java.security.InvalidKeyException;

/**
 * Helper class that is used for computing Macs (for i. e. information checking)
 */
public interface MacHelper {
    
    /**
     * Compute macs for the given data
     * 
     * @param data for which data do we need the mac?
     * @param key the key used for the macd tag that should be compared
     * @return mac for data (with key)
     * @throws InvalidKeyException 
     */
    public byte[] computeMAC(byte[] data, byte[] key) throws InvalidKeyException;

    
    /**
     * Verify mac for the given data
     * 
     * @param data for which data do we need the mac?
     * @param key the key used for the mac
     * @param tag the compute
     * @return true if it matches
     */
    public boolean verifyMAC(byte[] data, byte[] tag, byte[] key);
    
    /**
     * the size of the input key (in bytes) needed for the MAC. We could also
     * add an RandomSource to the class but I'm not too sure which way would be
     * more maintainable.
     * 
     * @return the needed input key size
     */
    public int keySize();
}
