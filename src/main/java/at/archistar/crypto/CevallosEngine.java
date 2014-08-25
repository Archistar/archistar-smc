package at.archistar.crypto;

import at.archistar.crypto.secretsharing.ShamirPSS;
import at.archistar.crypto.informationchecking.RabinBenOrRSS;
import at.archistar.crypto.informationchecking.CevallosUSRSS;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.decode.BerlekampWelchDecoderFactory;
import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.exceptions.ReconstructionException;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.mac.BCMacHelper;
import at.archistar.crypto.mac.BCShortenedMacHelper;
import at.archistar.crypto.mac.MacHelper;
import at.archistar.crypto.random.BCDigestRandomSource;
import at.archistar.crypto.random.RandomSource;
import java.security.NoSuchAlgorithmException;
import org.bouncycastle.crypto.macs.SipHash;

/**
 *
 * @author andy
 */
public class CevallosEngine implements CryptoEngine {
    private final RabinBenOrRSS algorithm;
    
    public CevallosEngine(int n, int k) throws NoSuchAlgorithmException, WeakSecurityException {
        
        /* component selection */
        RandomSource rng = new BCDigestRandomSource();
        MacHelper mac = new BCShortenedMacHelper(new BCMacHelper(new SipHash(2, 4), 128), k, CevallosUSRSS.E);
        DecoderFactory decoderFactory = new BerlekampWelchDecoderFactory();

        this.algorithm = new CevallosUSRSS(new ShamirPSS(n, k, rng, decoderFactory), mac, rng);
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
