package at.archistar.crypto.secretsharing;

import at.archistar.crypto.data.InvalidParametersException;
import at.archistar.crypto.data.Share;
import static at.archistar.crypto.data.Share.ENC_ALGORITHM;
import static at.archistar.crypto.data.Share.ENC_KEY;
import static at.archistar.crypto.data.Share.ORIGINAL_LENGTH;
import at.archistar.crypto.data.Share.ShareType;
import at.archistar.crypto.data.ShareFactory;
import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.decode.ErasureDecoder;
import at.archistar.crypto.math.DynamicOutputEncoderConverter;
import at.archistar.crypto.math.EncodingConverter;
import at.archistar.crypto.math.GF;
import at.archistar.crypto.math.OutputEncoderConverter;
import at.archistar.crypto.math.StaticOutputEncoderConverter;
import at.archistar.crypto.math.gf257.GF257;
import at.archistar.crypto.random.RandomSource;
import at.archistar.crypto.symmetric.Encryptor;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * <p>This class implements the Computational Secret Sharing scheme developed by Krawczyk.</p>
 *  
 * <p>This is a hybrid sheme that combines classical symmetric encryption, ShamirPSS
 * and RabinIDS. The secret data is initially encrypted using an traditional
 * symmetric encryption scheme (i.e. AES, Salsa, ChaCha..). The resulting encoded
 * data is then distributed between participants with the fast but insecure
 * RabinIDS scheme. The key that was used during the encryption is split up using
 * the slow but secure ShamirPSS scheme and also distributed between participants.
 * The performance benefit arises from the fact that the encryption key is many
 * times smaller then the encrypted data -- the (computation- and storage-wise)
 * inefficient shamir-pss algorithm thus performs only on small amounts of data
 * while the faster performing and more space-efficient rabin-ids algorithm is
 * used for the encrypted (larger) data.</p>
 * 
 * <p>For detailed information about this scheme, see: 
 * http://courses.csail.mit.edu/6.857/2009/handouts/short-krawczyk.pdf</p>
 */
public class KrawczykCSS extends BaseSecretSharing {
    
    private final RandomSource rng;
    
    private final GeometricSecretSharing shamir;
    
    private final GeometricSecretSharing rs;
    
    private final Encryptor cryptor;
    
    private final GF gf;
    
    /**
     * Constructor
     * (Applying the default settings for the Shamir-RNG and the decoders: {@link SHA1PRNG} and {@link ErasureDecoder})
     * 
     * @param n the number of shares
     * @param k the minimum number of shares required for reconstruction
     * @param rng the RandomSource to be used for the underlying Shamir-scheme
     * @param cryptor the to be used encryption algorithms
     * @throws WeakSecurityException thrown if this scheme is not secure for the given parameters
     */
    public KrawczykCSS(int n, int k, RandomSource rng,
                       Encryptor cryptor,
                       DecoderFactory decFactory, GF gf) throws WeakSecurityException {
        super(n, k);
        
        this.shamir = new ShamirPSS(n, k, rng, decFactory, gf);
        this.rs = new RabinIDS(n, k, decFactory, gf);
        this.cryptor = cryptor;
        this.rng = rng;
        this.gf = gf;
    }
    
    @Override
    public Share[] share(byte[] data) {
        try {
            /* encrypt the data */
            byte[] encKey = new byte[cryptor.getKeyLength()];
            this.rng.fillBytes(encKey);
            byte[] encSource =  cryptor.encrypt(data, encKey);

            /* share key and content */
            OutputEncoderConverter outputContent[] = new OutputEncoderConverter[n];
            OutputEncoderConverter outputKey[] = new OutputEncoderConverter[n];
            for (int i = 0; i < n; i++) {
                if (gf instanceof GF257) {
                    outputKey[i] = new DynamicOutputEncoderConverter(encKey.length, gf);
                    outputContent[i] = new DynamicOutputEncoderConverter(data.length, gf);
                } else {                
                    outputKey[i] = new StaticOutputEncoderConverter(encKey.length);
                    outputContent[i] = new StaticOutputEncoderConverter(data.length);
                }
            }

            rs.share(outputContent, encSource);
            shamir.share(outputKey, encKey);
            
            //Generate a new array of encrypted shares
            Share[] kshares = new Share[n];
            for (int i = 0; i < kshares.length; i++) {
                Map<Byte, byte[]> metadata = new HashMap<>();
                metadata.put(ORIGINAL_LENGTH, ByteBuffer.allocate(4).putInt(encSource.length).array());
                metadata.put(ENC_ALGORITHM, ByteBuffer.allocate(4).putInt(1).array());
                metadata.put(ENC_KEY, outputKey[i].getEncodedData());
                
                kshares[i] = ShareFactory.create(ShareType.KRAWCZYK, (byte)(i+1),
                                               outputContent[i].getEncodedData(),
                                               metadata);
            }

            return kshares;
        } catch (GeneralSecurityException | InvalidCipherTextException | IOException | InvalidParametersException e) {
            // encryption should actually never fail
            throw new RuntimeException("impossible: sharing failed (" + e.getMessage() + ")");
        }
    }

    @Override
    public byte[] reconstruct(Share[] shares) throws ReconstructionException {
        
        if (shares.length < k) {
            throw new ReconstructionException("to few shares");
        }
        
        try {
            int[] xValues = GeometricSecretSharing.extractXVals(shares, k);
            int originalLengthKey = shares[0].getMetadataArray(ENC_KEY).length;
            int originalLengthContent = shares[0].getMetadata(ORIGINAL_LENGTH);
            
            EncodingConverter[] ecKey = new EncodingConverter[shares.length];
            EncodingConverter[] ecContent = new EncodingConverter[shares.length];
            for (int i = 0; i < shares.length; i++) {
                ecKey[i] = new EncodingConverter(shares[i].getMetadataArray(ENC_KEY), gf);
                ecContent[i] = new EncodingConverter(shares[i].getYValues(), gf);
            }
            
            byte[] key = shamir.reconstruct(ecKey, xValues, originalLengthKey);
            byte[] encShare = rs.reconstruct(ecContent, xValues, originalLengthContent);
            
            return cryptor.decrypt(encShare, key);
        } catch (GeneralSecurityException | IOException | IllegalStateException | InvalidCipherTextException e) {
            // dencryption should actually never fail
            throw new RuntimeException("impossible: reconstruction failed (" + e.getMessage() + ")");
        }
    }
    
    @Override
    public String toString() {
        return "KrawczzkCSS(" + n + "/" + k + ", " + cryptor + ")";
    }
}
