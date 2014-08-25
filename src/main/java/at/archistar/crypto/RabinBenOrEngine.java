package at.archistar.crypto;

import at.archistar.crypto.secretsharing.KrawczykCSS;
import at.archistar.crypto.informationchecking.RabinBenOrRSS;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.decode.BerlekampWelchDecoderFactory;
import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.exceptions.ReconstructionException;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.mac.MacHelper;
import at.archistar.crypto.mac.ShareMacHelper;
import at.archistar.crypto.random.BCDigestRandomSource;
import at.archistar.crypto.random.RandomSource;
import at.archistar.crypto.symmetric.AESEncryptor;
import at.archistar.crypto.symmetric.Encryptor;
import java.security.NoSuchAlgorithmException;

/**
 *
 * @author andy
 */
public class RabinBenOrEngine implements CryptoEngine {
    private final RabinBenOrRSS algorithm;
    
    public RabinBenOrEngine(int n, int k) throws NoSuchAlgorithmException, WeakSecurityException {
        
        /* component selection */
        RandomSource rng = new BCDigestRandomSource();
        MacHelper mac = new ShareMacHelper("HMacSHA256");
        DecoderFactory decoderFactory = new BerlekampWelchDecoderFactory();
        Encryptor cryptor = new AESEncryptor();

        this.algorithm = new RabinBenOrRSS(new KrawczykCSS(n, k, rng, cryptor, decoderFactory), mac, rng);
        
    }

    @Override
    public Share[] share(byte[] data) {
        return this.algorithm.share(data);
    }

    @Override
    public byte[] reconstruct(Share[] shares) throws ReconstructionException {
        return this.algorithm.reconstruct(shares);
    }
}
