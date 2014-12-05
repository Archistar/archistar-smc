package at.archistar.crypto;

import at.archistar.crypto.data.Share;
import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.decode.ErasureDecoderFactory;
import at.archistar.crypto.secretsharing.ReconstructionException;
import at.archistar.crypto.secretsharing.WeakSecurityException;
import at.archistar.crypto.informationchecking.InformationChecking;
import at.archistar.crypto.informationchecking.RabinBenOrRSS;
import at.archistar.crypto.mac.BCPoly1305MacHelper;
import at.archistar.crypto.mac.MacHelper;
import at.archistar.crypto.math.GFFactory;
import at.archistar.crypto.math.gf256.GF256Factory;
import at.archistar.crypto.random.BCDigestRandomSource;
import at.archistar.crypto.random.RandomSource;
import at.archistar.crypto.secretsharing.KrawczykCSS;
import at.archistar.crypto.secretsharing.SecretSharing;
import at.archistar.crypto.symmetric.ChaCha20Encryptor;
import at.archistar.crypto.symmetric.Encryptor;
import java.security.NoSuchAlgorithmException;

/**
 * Implement a secret sharing engine based upon secure krawczywk sharing and
 * rabin-ben-or information checking scheme.
 */
public class RabinBenOrEngine implements CryptoEngine {
    
    /** the secret sharing scheme */
    private final SecretSharing sharing;
    
    /** the information checking algorithm that will be employed */
    private final InformationChecking ic;
    
    /** how many shares should be generated */
    private final int n;
    
    /** minimum amount of shares needed to reconstruct original data */
    private final int k;

    /**
     * Create a new Rabin-Ben-Or Engine utilizing the default random number
     * generator.
     * 
     * @param n total number of shares
     * @param k minimum count of shares needed to recreate the original data
     * 
     * @throws NoSuchAlgorithmException
     * @throws WeakSecurityException if the k/n selection is insecure
     */
    public RabinBenOrEngine(int n, int k) throws NoSuchAlgorithmException, WeakSecurityException {
        this(n, k, new BCDigestRandomSource());
    }

    /**
     * Create a new Rabin-Ben-Or Engine.
     * 
     * @param n total number of shares
     * @param k minimum count of shares needed to recreate the original data
     * @param rng random number generator to be used
     * 
     * @throws NoSuchAlgorithmException
     * @throws WeakSecurityException if the k/n selection is insecure
     */
    public RabinBenOrEngine(int n, int k, RandomSource rng) throws NoSuchAlgorithmException, WeakSecurityException {
        this.n = n;
        this.k = k;
        MacHelper mac = new BCPoly1305MacHelper();
        GFFactory gffactory = new GF256Factory();
        DecoderFactory decoderFactory = new ErasureDecoderFactory(gffactory);
        Encryptor cryptor = new ChaCha20Encryptor();
        this.sharing = new KrawczykCSS(n, k, rng, cryptor, decoderFactory, gffactory.createHelper());
        this.ic = new RabinBenOrRSS(k, mac, rng);
    }

    @Override
    public Share[] share(byte[] data) {
        return ic.createTags(sharing.share(data));
    }

    @Override
    public byte[] reconstruct(Share[] shares) throws ReconstructionException {
        return sharing.reconstruct(ic.checkShares(shares));
    }
    
    @Override
    public String toString() {
        return "Rabin-Ben-Or(Krawzywk(ChaCha20), Poly1305, " + k + "/" + n + ")";
    }
}
