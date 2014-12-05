package at.archistar.crypto.symmetric;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Security;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * basic AES-GCM based encryption
 * 
 * TODO: we are currently using a fixed IV!
 */
public class AESGCMEncryptor implements Encryptor {

    private final byte randomIvBytes[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    
    @Override
    public byte[] encrypt(byte[] data, byte[] randomKeyBytes) throws IOException, InvalidKeyException,
            InvalidAlgorithmParameterException, InvalidCipherTextException {

        AEADBlockCipher cipher = new GCMBlockCipher(new AESFastEngine());
        cipher.init(true, new AEADParameters(new KeyParameter(randomKeyBytes), 128, randomIvBytes));
        return cipherData(cipher, data);
    }

    private static byte[] cipherData(AEADBlockCipher cipher, byte[] data) throws IllegalStateException, InvalidCipherTextException {
        int minSize = cipher.getOutputSize(data.length);
        byte[] outBuf = new byte[minSize];
        int length1 = cipher.processBytes(data, 0, data.length, outBuf, 0);
        int length2 = cipher.doFinal(outBuf, length1);
        int actualLength = length1 + length2;
        byte[] result = new byte[actualLength];
        System.arraycopy(outBuf, 0, result, 0, result.length);
        return result;
    }

    @Override
    public byte[] decrypt(byte[] data, byte[] randomKey)
            throws InvalidKeyException, InvalidAlgorithmParameterException, IOException,
            IllegalStateException, InvalidCipherTextException {

        AEADBlockCipher cipher = new GCMBlockCipher(new AESFastEngine());
        cipher.init(false, new AEADParameters(new KeyParameter(randomKey), 128, randomIvBytes));
        return cipherData(cipher, data);
    }
    
    @Override
    public int getKeyLength() {
        return 32;
    }
    
    @Override
    public String toString() {
        return "AESGCMCryptor()";
    }
}
