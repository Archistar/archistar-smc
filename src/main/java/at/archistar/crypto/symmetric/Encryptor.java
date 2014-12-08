package at.archistar.crypto.symmetric;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * This interface describes possible symmetric encryption algorithms. 
 */
public interface Encryptor {
    
        /**
         * Encrypt data using this class
         * 
         * @param data the (secret) original data
         * @param randomKeyBytes the key to be used
         * @return encrypted data
         * @throws IOException if an serialization error occurs
         * @throws InvalidKeyException the supplied key was not sufficient
         *         for the algorithm
         * @throws InvalidAlgorithmParameterException the algorithm wasn't found
         * @throws InvalidCipherTextException  shouldn't happen
         */
        public byte[] encrypt(byte[] data, byte[] randomKeyBytes) throws IOException, InvalidKeyException,
            InvalidAlgorithmParameterException, InvalidCipherTextException;

        /**
         * Decrypt data using this class
         * 
         * @param data the (secret) original data
         * @param randomKeyBytes the key to be used
         * @return encrypted data
         * @throws IOException if an serialization error occurs
         * @throws InvalidKeyException the supplied key was not sufficient
         *         for the algorithm
         * @throws InvalidAlgorithmParameterException the algorithm wasn't found
         * @throws InvalidCipherTextException  shouldn't happen
         */
        public byte[] decrypt(byte[] data, byte[] randomKeyBytes)
            throws InvalidAlgorithmParameterException, InvalidKeyException, IOException, IllegalStateException, InvalidCipherTextException;
        
        /**
         * @return return the keylength needed by this algorithm
         */
        public int getKeyLength();
}
