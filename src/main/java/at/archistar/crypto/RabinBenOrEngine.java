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
import at.archistar.crypto.math.GFFactory;
import at.archistar.crypto.math.gf256.GF256Factory;
import at.archistar.crypto.random.BCDigestRandomSource;
import at.archistar.crypto.random.RandomSource;
import at.archistar.crypto.secretsharing.KrawczykCSS;
import at.archistar.crypto.secretsharing.BaseSecretSharing;
import at.archistar.crypto.symmetric.ChaCha20Encryptor;
import at.archistar.crypto.symmetric.Encryptor;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

/**
 * Implement a secret sharing engine based upon secure krawczywk sharing and
 * rabin-ben-or information checking scheme.
 */
public class RabinBenOrEngine implements CryptoEngine {
    private final BaseSecretSharing sharing;
    private final InformationChecking ic;
    
    private static final GFFactory gffactory = new GF256Factory();
    
    private final int n;
    
    private final int k;
    
    public RabinBenOrEngine(int n, int k) throws NoSuchAlgorithmException, WeakSecurityException {
        this(n, k, new BCDigestRandomSource());
    }
    
    public RabinBenOrEngine(int n, int k, RandomSource rng) throws NoSuchAlgorithmException, WeakSecurityException {
        this.n = n;
        this.k = k;
        MacHelper mac = new BCPoly1305MacHelper();
        DecoderFactory decoderFactory = new ErasureDecoderFactory(gffactory);
        Encryptor cryptor = new ChaCha20Encryptor();
        this.sharing = new KrawczykCSS(n, k, rng, cryptor, decoderFactory, gffactory.createHelper());
        this.ic = new RabinBenOrRSS(k, mac, rng);
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
    
    @Override
    public String toString() {
        return "Rabin-Ben-Or(Krawzywk(ChaCha20), Poly1305, " + k + "/" + n + ")";
    }
}
