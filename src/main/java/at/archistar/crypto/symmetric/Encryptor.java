/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package at.archistar.crypto.symmetric;

import at.archistar.crypto.exceptions.ImpossibleException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 *
 * @author andy
 */
public interface Encryptor {
        public byte[] encrypt(byte[] data, byte[] randomKeyBytes) throws IOException, InvalidKeyException,
            InvalidAlgorithmParameterException, InvalidCipherTextException, ImpossibleException;

        public byte[] decrypt(byte[] data, byte[] randomKeyBytes)
            throws InvalidAlgorithmParameterException, InvalidKeyException, IOException, IllegalStateException, InvalidCipherTextException, ImpossibleException;
        
        public int getKeyLength();
}
