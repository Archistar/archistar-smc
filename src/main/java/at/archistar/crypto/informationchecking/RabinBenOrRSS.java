package at.archistar.crypto.informationchecking;

import at.archistar.crypto.data.InformationCheckingShare;
import at.archistar.crypto.data.InvalidParametersException;
import at.archistar.crypto.mac.MacHelper;
import at.archistar.crypto.random.RandomSource;

import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * <p>This class implements the <i>Rabin-Ben-Or Robust Secret-Sharing </i> scheme.</p>
 *
 * <p>For a detailed description of the scheme,
 * see: <a href="http://www.cse.huji.ac.il/course/2003/ns/Papers/RB89.pdf">http://www.cse.huji.ac.il/course/2003/ns/Papers/RB89.pdf</a></p>
 */
public class RabinBenOrRSS implements InformationChecking {

    /** minimum amount of shares needed for reconstructing the secret */
    protected final int k;
    private final MacHelper mac;
    private final RandomSource rng;

    /**
     * Constructor
     *
     * @param mac the mac that will be used
     * @param rng the mac will need a random number source
     */
    public RabinBenOrRSS(int k, MacHelper mac, RandomSource rng) {
        this.mac = mac;
        this.rng = rng;
        this.k = k;
    }

    @Override
    public InformationCheckingShare[] createTags(InformationCheckingShare[] rboshares) throws InvalidParametersException {
        /* compute and add the corresponding tags */
        for (InformationCheckingShare share1 : rboshares) {
            if (share1.getICType() != InformationCheckingShare.ICType.RABIN_BEN_OR) {
                throw new InvalidParametersException("Share is not a Rabin-Ben-Or IC Share");
            }

            for (InformationCheckingShare share2 : rboshares) {
                try {
                    byte[] key = new byte[this.mac.keySize()];
                    this.rng.fillBytes(key);
                    byte[] tag = this.mac.computeMAC(share1.getYValues(), key);

                    share1.getMacs().put(share2.getId(), tag);
                    share2.getMacKeys().put(share1.getId(), key);
                } catch (InvalidKeyException e) {
                    throw new RuntimeException("this cannot happen");
                }
            }
        }
        return rboshares;
    }

    @Override
    public Map<Boolean, List<InformationCheckingShare>> checkShares(InformationCheckingShare[] shares) {
        return Arrays.stream(shares).collect(Collectors.partitioningBy(
                share -> Arrays.stream(shares).filter(
                        s -> mac.verifyMAC(
                                share.getYValues(),
                                share.getMacs().get(s.getId()),
                                s.getMacKeys().get(share.getId()))
                ).count() >= k
        ));
    }

    @Override
    public String toString() {
        return "RabinBenOr(k=" + k + ", " + mac + ")";
    }
}
