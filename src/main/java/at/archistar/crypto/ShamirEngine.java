package at.archistar.crypto;

import at.archistar.crypto.data.Share;
import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.decode.ErasureDecoderFactory;
import at.archistar.crypto.informationchecking.RabinBenOrRSS;
import at.archistar.crypto.mac.BCPoly1305MacHelper;
import at.archistar.crypto.mac.MacHelper;
import at.archistar.crypto.random.BCDigestRandomSource;
import at.archistar.crypto.random.RandomSource;
import at.archistar.crypto.secretsharing.ReconstructionException;
import at.archistar.crypto.secretsharing.ShamirPSS;
import at.archistar.crypto.secretsharing.WeakSecurityException;

import java.security.NoSuchAlgorithmException;

/**
 * This is a simple CryptoEngine that allows us to use ITS secret-sharing scheme
 * plus Rabin-Ben-Or information checking
 *
 * @author Andreas Happe <andreashappe@snikt.net>
 */
public class ShamirEngine implements CryptoEngine {

    /** our ITS Shamir secret-sharing scheme */
    private final ShamirPSS sharing;

    private final RabinBenOrRSS ic;

    /** how many shares should be generated */
    private final int n;

    /** minimum amount of shares needed to reconstruct original data */
    private final int k;

    /**
     * initialize the crypto engine
     *
     * @param n total number of shares
     * @param k minimum count of shares needed to recreate the original data
     * @throws WeakSecurityException if the k/n selection is insecure
     */
    public ShamirEngine(int n, int k) throws NoSuchAlgorithmException, WeakSecurityException {
        this(n, k, new BCDigestRandomSource());
    }

    /**
     * Create a new Shamir Engine.
     *
     * @param n total number of shares
     * @param k minimum count of shares needed to recreate the original data
     * @param rng random number generator to be used
     * @throws WeakSecurityException if the k/n selection is insecure
     */
    public ShamirEngine(int n, int k, RandomSource rng) throws NoSuchAlgorithmException, WeakSecurityException {
        DecoderFactory decoderFactory = new ErasureDecoderFactory();
        MacHelper mac = new BCPoly1305MacHelper();

        this.sharing = new ShamirPSS(n, k, rng, decoderFactory);
        this.ic = new RabinBenOrRSS(k, mac, rng);
        this.n = n;
        this.k = k;
    }

    @Override
    public Share[] share(byte[] data) {
        return ic.createTags(sharing.share(data));
    }

    @Override
    public byte[] reconstruct(Share[] shares) throws ReconstructionException {
        return this.sharing.reconstruct(ic.checkShares(shares));
    }

    @Override
    public byte[] reconstructPartial(Share[] shares, long start) throws ReconstructionException {
        for (Share s : shares) {
            s.setInformationChecking(Share.ICType.NONE);
        }
        System.err.println("*** WARNING: Partial reconstruction -- no Information Checking is performed");
        return this.sharing.reconstructPartial(shares, start);
    }

    @Override
    public String toString() {
        return "Shamir(" + k + "/" + n + ")";
    }
}
