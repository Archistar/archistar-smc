package at.archistar.crypto;

import at.archistar.crypto.data.SerializableShare;
import at.archistar.crypto.secretsharing.ShamirPSS;
import at.archistar.crypto.informationchecking.CevallosUSRSS;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.data.VSSShare;
import at.archistar.crypto.decode.BerlekampWelchDecoderFactory;
import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.exceptions.ImpossibleException;
import at.archistar.crypto.exceptions.ReconstructionException;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.informationchecking.InformationChecking;
import at.archistar.crypto.mac.BCMacHelper;
import at.archistar.crypto.mac.BCShortenedMacHelper;
import at.archistar.crypto.mac.MacHelper;
import at.archistar.crypto.random.BCDigestRandomSource;
import at.archistar.crypto.random.RandomSource;
import at.archistar.crypto.secretsharing.SecretSharing;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import org.bouncycastle.crypto.macs.SipHash;

/**
 *
 * @author andy
 */
public class CevallosEngine implements CryptoEngine {
    private final SecretSharing sharing;
    private final InformationChecking ic;

    public CevallosEngine(int n, int k) throws NoSuchAlgorithmException, WeakSecurityException {
        /* component selection */
        RandomSource rng = new BCDigestRandomSource();
        MacHelper mac = new BCShortenedMacHelper(new BCMacHelper(new SipHash(2, 4), 128), k, CevallosUSRSS.E);
        DecoderFactory decoderFactory = new BerlekampWelchDecoderFactory();

        this.sharing = new ShamirPSS(n, k, rng, decoderFactory);
        this.ic = new CevallosUSRSS(sharing, mac, rng);
    }
    
    public CevallosEngine(int n, int k, RandomSource rng) throws NoSuchAlgorithmException, WeakSecurityException {
        /* component selection */
        MacHelper mac = new BCShortenedMacHelper(new BCMacHelper(new SipHash(2, 4), 128), k, CevallosUSRSS.E);
        DecoderFactory decoderFactory = new BerlekampWelchDecoderFactory();

        this.sharing = new ShamirPSS(n, k, rng, decoderFactory);
        this.ic = new CevallosUSRSS(sharing, mac, rng);
    }

@Override
    public Share[] share(byte[] data) throws WeakSecurityException {
        
        SerializableShare[] shares = (SerializableShare[])sharing.share(data);
        VSSShare[] vssshares = new VSSShare[shares.length];
        
        for (int i = 0; i < shares.length; i++) {
            vssshares[i] = new VSSShare(shares[i]);
        }

        try {
            ic.createTags(vssshares);
        } catch (IOException ex) {
            throw new ImpossibleException("error while creating tags: " + ex);
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
