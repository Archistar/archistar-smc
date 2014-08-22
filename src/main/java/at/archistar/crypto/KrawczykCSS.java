package at.archistar.crypto;

import at.archistar.crypto.data.KrawczykShare;
import at.archistar.crypto.data.KrawczykShare.EncryptionAlgorithm;
import at.archistar.crypto.data.ReedSolomonShare;
import at.archistar.crypto.data.ShamirShare;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.decode.ErasureDecoder;
import at.archistar.crypto.exceptions.CryptoException;
import at.archistar.crypto.exceptions.ImpossibleException;
import at.archistar.crypto.exceptions.ReconstructionException;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.random.RandomSource;
import at.archistar.crypto.random.SHA1PRNG;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * <p>This class implements the <i>Computational Secret Sharing</i> scheme developed by Krawczyk.</p>
 *  
 * <p>In short, this system combines the insecure but very fast and most importantly space efficient {@link ReedSolomon} 
 * with symmetric encryption with the perfectly secure {@link ShamirPSS} for sharing the key.</p>
 * 
 * <p>For detailed information about this scheme, see: 
 * <a href="http://courses.csail.mit.edu/6.857/2009/handouts/short-krawczyk.pdf">http://courses.csail.mit.edu/6.857/2009/handouts/short-krawczyk.pdf</a></p>
 * 
 * <p><b>NOTE:</b> This implementation uses <i>AES-128 in CBC-mode with PKCS5Padding</i> for encrypting the secret.</p>
 * 
 * @author Elias Frantar
 * @author Andreas Happe <andreashappe@snikt.net>
 * @author Thomas Loruenser <thomas.loruenser@ait.ac.at>
 * @version 2014-7-28
 */
public class KrawczykCSS extends SecretSharing {
    private EncryptionAlgorithm alg = EncryptionAlgorithm.AES;
    private static final int KEY_LENGTH = 128;
    
    private final SecretSharing shamir;
    private final SecretSharing rs;
    
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Constructor
     * (Applying the default settings for the Shamir-RNG and the decoders: {@link SHA1PRNG} and {@link ErasureDecoder})
     * 
     * @param n the number of shares
     * @param k the minimum number of shares required for reconstruction
     * @param rng the RandomSource to be used for the underlying Shamir-scheme
     * @throws WeakSecurityException thrown if this scheme is not secure for the given parameters
     */
    public KrawczykCSS(int n, int k, RandomSource rng) throws WeakSecurityException {
        this(n, k, rng, EncryptionAlgorithm.AES);
    }

    /**
     * Constructor
     * (Applying the default settings for the Shamir-RNG and the decoders: {@link SHA1PRNG} and {@link ErasureDecoder})
     * 
     * @param n the number of shares
     * @param k the minimum number of shares required for reconstruction
     * @param rng the RandomSource to be used for the underlying Shamir-scheme
     * @param alg the to be used encryption algorithms
     * @throws WeakSecurityException thrown if this scheme is not secure for the given parameters
     */
    public KrawczykCSS(int n, int k, RandomSource rng, EncryptionAlgorithm alg) throws WeakSecurityException {
        super(n, k);
        
        shamir = new ShamirPSS(n, k, rng); // use a SharmirSecretSharing share generator to share the key and the content
        rs = new RabinIDS(n, k); // use RabinIDS for sharing Content 
        this.alg = alg;
    }

    
    @Override
    public Share[] share(byte[] data) {
        try {
            /* encrypt the data */
            byte[] encKey = genRandomSecretKey(alg.getAlgString(), KEY_LENGTH);
            byte[] encSource =  crypt(Cipher.ENCRYPT_MODE, alg.getAlgString(), encKey, data);

            /* share key and content */
            Share[] contentShares = rs.share(encSource); // since the content is encrypted the share does not have to be perfectly secure (-> Reed-Solomon-Code)
            Share[] keyShares = shamir.share(encKey);

            //Generate a new array of encrypted shares
            return createKrawczykShares((ShamirShare[]) keyShares, (ReedSolomonShare[]) contentShares, alg);
        } catch (CryptoException e) { 
            // encryption should actually never fail
            throw new ImpossibleException("sharing failed (" + e.getMessage() + ")");
        } catch (NoSuchAlgorithmException e) { 
            // encryption should actually never fail
            throw new ImpossibleException("sharing failed (" + e.getMessage() + ")");
        } catch (InvalidKeyException ex) {
            Logger.getLogger(KrawczykCSS.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(KrawczykCSS.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(KrawczykCSS.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(KrawczykCSS.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(KrawczykCSS.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(KrawczykCSS.class.getName()).log(Level.SEVERE, null, ex);
        }
        return new Share[0];
    }

    @Override
    public byte[] reconstruct(Share[] shares) throws ReconstructionException {
        try {   
            KrawczykShare[] kshares = safeCast(shares);
            
            byte[] key = shamir.reconstruct(extractKeyShares(kshares)); // reconstruct the key
            byte[] encShare = rs.reconstruct(extractContentShares(kshares)); // reconstruct the encrypted share

            return crypt(Cipher.DECRYPT_MODE, alg.getAlgString(), key, encShare);
        } catch (CryptoException e) {
            throw new ReconstructionException();
        } catch (InvalidKeyException ex) {
            Logger.getLogger(KrawczykCSS.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(KrawczykCSS.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(KrawczykCSS.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(KrawczykCSS.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(KrawczykCSS.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(KrawczykCSS.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(KrawczykCSS.class.getName()).log(Level.SEVERE, null, ex);
        }
        return new byte[0];
    }
    
    /**
     * Converts the Share[] to a KrawczykShare[] by casting each element individually.
     * 
     * @param shares the shares to cast
     * @return the given Share[] as KrawczykShare[]
     * @throws ClassCastException if the Share[] did not (only) contain KrawczykShare
     */
    private KrawczykShare[] safeCast(Share[] shares) {
        KrawczykShare[] kshares = new KrawczykShare[shares.length];
        
        for (int i = 0; i < shares.length; i++) {
            kshares[i] = (KrawczykShare) shares[i];
        }
        
        return kshares;
    }
    
    /**
     * Create <i>n</i> KrawczykShares from the given Shamir- and Reed-Solomon shares.
     * @param sshares the ShamirShares (key-shares)
     * @param rsshares the ReedSolomonShares (content-shares)
     * @param algorithm the algorithm used for encryption
     * @return an array with the created shares
     */
    private static KrawczykShare[] createKrawczykShares(ShamirShare[] sshares, ReedSolomonShare[] rsshares, EncryptionAlgorithm algorithm) {
        assert sshares.length == rsshares.length; // both Share[] must have the same length
        
        KrawczykShare[] kshares = new KrawczykShare[sshares.length];
        for (int i = 0; i < kshares.length; i++) {
            kshares[i] = new KrawczykShare((byte) rsshares[i].getId(), rsshares[i].getY(), rsshares[i].getOriginalLength(), sshares[i].getY(), algorithm);
        }
        
        return kshares;
    }
    
    /**
     * Extracts the key-shares from the given KrawczykShares.
     * @param kshares the shares to extract the key-shares from
     * @return an array of the extracted key-shares
     */
    private static ShamirShare[] extractKeyShares(KrawczykShare[] kshares) {
        ShamirShare[] sshares = new ShamirShare[kshares.length];
        
        for (int i = 0; i < kshares.length; i++) {
            sshares[i] = new ShamirShare((byte) kshares[i].getId(), kshares[i].getKeyY());
        }
        
        return sshares;
    }
    
    /**
     * Extracts the content-shares from the given KrawczykShares.
     * @param kshares the shares to extract the content-shares from
     * @return an array of the extracted content-shares
     */
    private static ReedSolomonShare[] extractContentShares(KrawczykShare[] kshares) {
        ReedSolomonShare[] rsshares = new ReedSolomonShare[kshares.length];
        
        for (int i = 0; i < kshares.length; i++) {
            rsshares[i] = new ReedSolomonShare((byte) kshares[i].getId(), kshares[i].getY(), kshares[i].getOriginalLength());
        }
        
        return rsshares;
    }
    
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
     * Performs either encryption or decryption on the given data with the specified parameters.
     * @see #encrypt(String, byte[], byte[])
     * @see #decrypt(String, byte[], byte[])
     */
    private static byte[] crypt(int cipherMode, String algorithm, byte[] sKey, byte[] data)
            throws CryptoException, InvalidKeyException, InvalidAlgorithmParameterException,
                   NoSuchAlgorithmException, IllegalBlockSizeException,
                   NoSuchPaddingException, BadPaddingException,
                   NoSuchProviderException {
        
        SecretKeySpec sKeySpec = new SecretKeySpec(sKey, algorithm.split("/")[0]);
        
        /* always use bouncy castle provider */
        Cipher cipher = Cipher.getInstance(algorithm, "BC");
        cipher.init(cipherMode, sKeySpec, new IvParameterSpec(sKey));
        return cipher.doFinal(data);
    }
}
