package at.archistar.crypto.mac;

import java.security.InvalidKeyException;

/**
 *
 * @author andy
 */
public interface MacHelper {
    public byte[] computeMAC(byte[] data, byte[] key) throws InvalidKeyException;
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
