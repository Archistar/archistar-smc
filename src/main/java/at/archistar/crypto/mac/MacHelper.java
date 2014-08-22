package at.archistar.crypto.mac;

import java.security.InvalidKeyException;

/**
 *
 * @author andy
 */
public interface MacHelper {
    public byte[] computeMAC(byte[] data, byte[] key) throws InvalidKeyException;
    public boolean verifyMAC(byte[] data, byte[] tag, byte[] key);
}
