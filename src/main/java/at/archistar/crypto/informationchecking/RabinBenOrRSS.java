package at.archistar.crypto.informationchecking;

import at.archistar.crypto.data.Share;
import at.archistar.crypto.data.VSSShare;
import at.archistar.crypto.exceptions.ImpossibleException;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.mac.MacHelper;
import at.archistar.crypto.random.RandomSource;
import at.archistar.crypto.secretsharing.RabinIDS;
import at.archistar.crypto.secretsharing.SecretSharing;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.Arrays;

/**
 * <p>This class implements the <i>Rabin-Ben-Or Robust Secret-Sharing </i> scheme.</p>
 * 
 * <p>For a detailed description of the scheme, 
 * see: <a href="http://www.cse.huji.ac.il/course/2003/ns/Papers/RB89.pdf">http://www.cse.huji.ac.il/course/2003/ns/Papers/RB89.pdf</a></p>
 */
public class RabinBenOrRSS implements InformationChecking {

    private final SecretSharing sharing;
    private final MacHelper mac;
    private final RandomSource rng;

    /**
     * Constructor
     * 
     * @param sharing the Secret-Sharing algorithm to use as a base for this scheme (must not be itself!)
     * @param mac the mac that will be used
     * @throws WeakSecurityException 
     */
    public RabinBenOrRSS(SecretSharing sharing, MacHelper mac, RandomSource rng) throws WeakSecurityException {

        this.sharing = sharing;
        this.mac = mac;
        this.rng = rng;
        
        if (sharing instanceof RabinIDS) {
            throw new ImpossibleException("Reed-Solomon-Code is not secure!");
        }
    }
    
    @Override
    public void createTags(VSSShare[] rboshares) throws IOException {
        /* compute and add the corresponding tags */
        for (VSSShare share1 : rboshares) {
            for (VSSShare share2 : rboshares) {
                try {
                    byte[] key = new byte[this.mac.keySize()/8];
                    this.rng.fillBytes(key);
                    byte[] tag = this.mac.computeMAC(share1.getShare().serialize(), key);
                    
                    share1.getMacs().put((byte) share2.getId(), tag);
                    share2.getMacKeys().put((byte) share1.getId(), key);
                } catch (InvalidKeyException e) {
                    throw new ImpossibleException("this cannot happen");
                }
            }
        }        
    }

    @Override
    public Share[] checkShares(VSSShare[] rboshares) throws IOException {
        Share[] valid = new Share[rboshares.length];
        int counter = 0;
        
        for (int i = 0; i < rboshares.length; i++) { // go through all shares
            int accepts = 0; // number of participants accepting i
            for (VSSShare rboshare: rboshares) { // go through all shares
                
                byte[] data = rboshares[i].getShare().serialize();
                byte[] macCmp = rboshares[i].getMacs().get((byte) rboshare.getId());
                byte[] macKey = rboshare.getMacKeys().get((byte) rboshares[i].getId());
                
                if (mac.verifyMAC(data, macCmp, macKey)) {
                    accepts++;
                }
            }
            
            if (accepts >= sharing.getK()) { // if there are at least k accepts, this share is counted as valid
                valid[counter++] = rboshares[i];
            }
        }
        return Arrays.copyOfRange(valid, 0, counter);
    }

    @Override
    public String toString() {
        return "RabinBenOr(" + sharing + ", " + mac + ")";
    }
}
