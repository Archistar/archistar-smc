package at.archistar.crypto;

import at.archistar.crypto.data.Share;
import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.decode.ErasureDecoderFactory;
import at.archistar.crypto.math.GFFactory;
import at.archistar.crypto.math.gf256.GF256Factory;
import at.archistar.crypto.random.BCDigestRandomSource;
import at.archistar.crypto.secretsharing.ReconstructionException;
import at.archistar.crypto.secretsharing.SecretSharing;
import at.archistar.crypto.secretsharing.ShamirPSS;
import at.archistar.crypto.secretsharing.WeakSecurityException;

/**
 * This is a simple CryptoEngine that allows us to use ITS secret-sharing scheme.
 * 
 * @author Andreas Happe <andreashappe@snikt.net>
 */
public class ShamirEngine implements CryptoEngine {

    /** our ITS Shamir secret-sharing scheme */
    private final SecretSharing shamir;
 
    /**
     * initialize the crypto engine
     * 
     * @param n total number of shares
     * @param k minimum count of shares needed to recreate the original data
     * 
     * @throws WeakSecurityException if the k/n selection is insecure
     */
    public ShamirEngine(int n, int k) throws WeakSecurityException {
        
        GFFactory gffactory = new GF256Factory();
        DecoderFactory decoderFactory = new ErasureDecoderFactory(gffactory);
        BCDigestRandomSource rng = new BCDigestRandomSource();
        
        this.shamir = new ShamirPSS(n, k, rng, decoderFactory, gffactory.createHelper());
    }
    
    @Override
    public Share[] share(byte[] data) {
        return this.shamir.share(data);
    }

    @Override
    public byte[] reconstruct(Share[] shares) throws ReconstructionException {
        return this.shamir.reconstruct(shares);
    }
}
