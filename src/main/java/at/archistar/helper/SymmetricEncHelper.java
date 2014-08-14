package at.archistar.helper;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import at.archistar.crypto.exceptions.CryptoException;

/**
 * A little helper-class for performing symmetric encryption.
 * 
 * @author Elias Frantar
 * @version 2014-7-28
 */
public class SymmetricEncHelper {
    private SymmetricEncHelper() {} // we don't want any instances of this class
    
    /**
     * Generates a random secret key of specified length for the specified algorithm.
     * 
     * @param algorithm the algorithm to generate the key for (for example <i>"AES/CTR/PKCS5Padding"</i>)
     * @param length the length of the key
     * @return a randomly generated secret key of specified length
     * @throws NoSuchAlgorithmException thrown if the specified algorithm is not supported
     */
    public static byte[] genRandomSecretKey(String algorithm, int length) throws NoSuchAlgorithmException {
        KeyGenerator kgen = KeyGenerator.getInstance(algorithm.split("/")[0]);
        return kgen.generateKey().getEncoded();
    }
    
    /**
     * Encrypts the given data.
     * 
     * @param algorithm the algorithm to encrypt with
     * @param sKey the secret key to use for encryption
     * @param data the data to encrypt
     * @return the encrypted data
     * @throws CryptoException thrown if something went wrong during encryption
     */
    public static byte[] encrypt(String algorithm, byte[] sKey, byte[] data) throws CryptoException {
        return crypt(Cipher.ENCRYPT_MODE, algorithm, sKey, data);
    }
    /**
     * Decrypts the given data.
     * 
     * @param algorithm the algorithm to decrypt with
     * @param sKey the secret key to use for decryption
     * @param data the data to decrypt
     * @return the decrypted data
     * @throws CryptoException thrown if something went wrong during decryption
     */
    public static byte[] decrypt(String algorithm, byte[] sKey, byte[] data) throws CryptoException {
        return crypt(Cipher.DECRYPT_MODE, algorithm, sKey, data);
    }

    /**
     * Performs either encryption or decryption on the given data with the specified parameters.
     * @see #encrypt(String, byte[], byte[])
     * @see #decrypt(String, byte[], byte[])
     */
    private static byte[] crypt(int cipherMode, String algorithm, byte[] sKey, byte[] data) throws CryptoException {
        try {
            SecretKeySpec sKeySpec = new SecretKeySpec(sKey, algorithm.split("/")[0]);
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(cipherMode, sKeySpec, new IvParameterSpec(sKey)); // TODO: IV == key ???
            
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("en- or decrypting failed (cause: " + e.toString() + ")");
        } catch (InvalidKeyException e) {
            throw new CryptoException("en- or decrypting failed (cause: " + e.toString() + ")");
        } catch (GeneralSecurityException e) {
            throw new CryptoException("en- or decrypting failed (cause: " + e.toString() + ")");
        }
    }
}
