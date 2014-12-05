package at.archistar.crypto.symmetric;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * This interface describes possible symmetric encryption algorithms. 
 */
public interface Encryptor {
        public byte[] encrypt(byte[] data, byte[] randomKeyBytes) throws IOException, InvalidKeyException,
            InvalidAlgorithmParameterException, InvalidCipherTextException;

        public byte[] decrypt(byte[] data, byte[] randomKeyBytes)
            throws InvalidAlgorithmParameterException, InvalidKeyException, IOException, IllegalStateException, InvalidCipherTextException;
        
        public int getKeyLength();
}
