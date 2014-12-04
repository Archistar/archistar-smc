package at.archistar.crypto;

import at.archistar.crypto.data.Share;
import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.decode.ErasureDecoderFactory;
import at.archistar.crypto.exceptions.ReconstructionException;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.informationchecking.InformationChecking;
import at.archistar.crypto.informationchecking.RabinBenOrRSS;
import at.archistar.crypto.mac.BCPoly1305MacHelper;
import at.archistar.crypto.mac.MacHelper;
import at.archistar.crypto.mac.ShareMacHelper;
import at.archistar.crypto.math.GFFactory;
import at.archistar.crypto.math.gf256.GF256Factory;
import at.archistar.crypto.random.BCDigestRandomSource;
import at.archistar.crypto.random.RandomSource;
import at.archistar.crypto.secretsharing.KrawczykCSS;
import at.archistar.crypto.secretsharing.BaseSecretSharing;
import at.archistar.crypto.symmetric.AESEncryptor;
import at.archistar.crypto.symmetric.ChaCha20Encryptor;
import at.archistar.crypto.symmetric.Encryptor;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

/**
 *
 * @author andy
 */
public class RabinBenOrEngine implements CryptoEngine {
    private final BaseSecretSharing sharing;
    private final InformationChecking ic;
    
    private static final GFFactory gffactory = new GF256Factory();
    
    public RabinBenOrEngine(int n, int k) throws NoSuchAlgorithmException, WeakSecurityException {
        /* component selection */
        RandomSource rng = new BCDigestRandomSource();
        MacHelper mac = new BCPoly1305MacHelper();
        DecoderFactory decoderFactory = new ErasureDecoderFactory(gffactory);
        Encryptor cryptor = new ChaCha20Encryptor();
        this.sharing = new KrawczykCSS(n, k, rng, cryptor, decoderFactory, gffactory.createHelper());
        this.ic = new RabinBenOrRSS(sharing, mac, rng);
    }
    
    public RabinBenOrEngine(int n, int k, RandomSource rng) throws NoSuchAlgorithmException, WeakSecurityException {
        /* component selection */
        MacHelper mac = new ShareMacHelper("HMacSHA256");
        DecoderFactory decoderFactory = new ErasureDecoderFactory(gffactory);
        Encryptor cryptor = new AESEncryptor();
        this.sharing = new KrawczykCSS(n, k, rng, cryptor, decoderFactory, gffactory.createHelper());
        this.ic = new RabinBenOrRSS(sharing, mac, rng);
    }

    @Override
    public Share[] share(byte[] data) {
        
        Share[] shares = sharing.share(data);
        try {
            ic.createTags(shares);
        } catch (IOException ex) {
            throw new RuntimeException("impossible: how can creating tags fail?", ex);
        }
        return shares;
    }

    @Override
    public byte[] reconstruct(Share[] shares) throws ReconstructionException {
        Share[] valid;
        try {
            valid = ic.checkShares(shares);
            if (valid.length >= sharing.getK()) {
                return sharing.reconstruct(shares);
            }
        } catch (IOException ex) {
            throw new ReconstructionException("error in checkShares: " + ex.getMessage());
        }
        throw new ReconstructionException("valid.length (" + valid.length + ") <= k (" + sharing.getK() +")");
    }
}
