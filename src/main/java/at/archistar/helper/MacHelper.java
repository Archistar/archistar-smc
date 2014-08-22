package at.archistar.helper;

import at.archistar.crypto.data.Share;
import java.security.InvalidKeyException;

/**
 *
 * @author andy
 */
public interface MacHelper {
    public byte[] computeMAC(Share share, byte[] key) throws InvalidKeyException;
    public boolean verifyMAC(Share share, byte[] tag, byte[] key);
    public byte[] computeMAC(Share share, byte[] key, int length) throws InvalidKeyException;

}
