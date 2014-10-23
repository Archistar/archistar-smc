package at.archistar.crypto;

import at.archistar.crypto.data.SerializableShare;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.data.VSSShare;
import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.decode.ErasureDecoderFactory;
import at.archistar.crypto.exceptions.ReconstructionException;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.informationchecking.InformationChecking;
import at.archistar.crypto.informationchecking.RabinBenOrRSS;
import at.archistar.crypto.mac.MacHelper;
import at.archistar.crypto.mac.ShareMacHelper;
import at.archistar.crypto.math.GFFactory;
import at.archistar.crypto.math.gf256.GF256Factory;
import at.archistar.crypto.random.BCDigestRandomSource;
import at.archistar.crypto.random.RandomSource;
import at.archistar.crypto.secretsharing.KrawczykCSS;
import at.archistar.crypto.secretsharing.SecretSharing;
import at.archistar.crypto.symmetric.AESEncryptor;
import at.archistar.crypto.symmetric.Encryptor;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author andy
 */
public class RabinBenOrEngine implements CryptoEngine {
    private final SecretSharing sharing;
    private final InformationChecking ic;
    
    private static final GFFactory gffactory = new GF256Factory();
    
    public RabinBenOrEngine(int n, int k) throws NoSuchAlgorithmException, WeakSecurityException {
        /* component selection */
        RandomSource rng = new BCDigestRandomSource();
        MacHelper mac = new ShareMacHelper("HMacSHA256");
        DecoderFactory decoderFactory = new ErasureDecoderFactory(gffactory);
        Encryptor cryptor = new AESEncryptor();
        this.sharing = new KrawczykCSS(n, k, rng, cryptor, decoderFactory);
        this.ic = new RabinBenOrRSS(sharing, mac, rng);
    }
    
    public RabinBenOrEngine(int n, int k, RandomSource rng) throws NoSuchAlgorithmException, WeakSecurityException {
        /* component selection */
        MacHelper mac = new ShareMacHelper("HMacSHA256");
        DecoderFactory decoderFactory = new ErasureDecoderFactory(gffactory);
        Encryptor cryptor = new AESEncryptor();
        this.sharing = new KrawczykCSS(n, k, rng, cryptor, decoderFactory);
        this.ic = new RabinBenOrRSS(sharing, mac, rng);
    }

    @Override
    public Share[] share(byte[] data) {
        
        SerializableShare[] shares = (SerializableShare[])sharing.share(data);
        VSSShare[] vssshares = new VSSShare[shares.length];
        
        for (int i = 0; i < shares.length; i++) {
            try {
                vssshares[i] = new VSSShare(shares[i]);
            } catch (WeakSecurityException ex) {
                Logger.getLogger(RabinBenOrRSS.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        try {
            ic.createTags(vssshares);
        } catch (IOException ex) {
            Logger.getLogger(RabinBenOrRSS.class.getName()).log(Level.SEVERE, null, ex);
        }
        return vssshares;
    }

    @Override
    public byte[] reconstruct(Share[] shares) throws ReconstructionException {
        VSSShare[] rboshares = Arrays.copyOf(shares, shares.length, VSSShare[].class);

        Share[] valid;
        try {
            valid = ic.checkShares(rboshares);
            if (valid.length >= sharing.getK()) {
                return sharing.reconstruct(VSSShare.getInnerShares(rboshares));
            }
        } catch (IOException ex) {
            throw new ReconstructionException("error in checkShares: " + ex.getMessage());
        }
        throw new ReconstructionException("valid.length (" + valid.length + ") <= k (" + sharing.getK() +")");
    }
}
