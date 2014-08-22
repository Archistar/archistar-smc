package at.archistar.crypto;

import at.archistar.crypto.data.Share;
import at.archistar.crypto.data.VSSShare;
import at.archistar.crypto.exceptions.ImpossibleException;
import at.archistar.crypto.exceptions.ReconstructionException;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.random.RandomSource;
import at.archistar.crypto.mac.MacHelper;
import java.security.InvalidKeyException;
import java.util.Arrays;

/**
 * <p>This class implements the <i>Rabin-Ben-Or Robust Secret-Sharing </i> scheme.</p>
 * 
 * <p>For a detailed description of the scheme, 
 * see: <a href="http://www.cse.huji.ac.il/course/2003/ns/Papers/RB89.pdf">http://www.cse.huji.ac.il/course/2003/ns/Papers/RB89.pdf</a></p>
 * 
 * 
 * @author Elias Frantar
 * @author Andreas Happe <andreashappe@snikt.net>
 * @author Thomas Loruenser <thomas.loruenser@ait.ac.at>
 * @version 2014-7-24
 */
public class RabinBenOrRSS extends SecretSharing {
    private static final int KEY_LENGTH = 16;
    private static final int TAG_LENGTH = 32;
    
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
        super(sharing.getN(), sharing.getK());
        
        this.mac = mac;
        this.rng = rng;
        
        if (sharing instanceof RabinBenOrRSS) {
            throw new IllegalArgumentException("the underlying scheme must not be itself");
        }

        if (sharing instanceof RabinIDS) {
            throw new ImpossibleException("Reed-Solomon-Code is not secure!");
        }
        
        this.sharing = sharing;
    }

    @Override
    public Share[] share(byte[] data) {
        VSSShare[] rboshares = VSSShare.createVSSShares(sharing.share(data), TAG_LENGTH, KEY_LENGTH);
        
        /* compute and add the corresponding tags */
        for (VSSShare share1 : rboshares) {
            for (VSSShare share2 : rboshares) {
                try {
                    byte[] key = new byte[KEY_LENGTH];
                    this.rng.fillBytes(key);
                    byte[] tag = mac.computeMAC(share1.getShare().serialize(), key);
                    assert(TAG_LENGTH == tag.length);
                    
                    share1.getMacs().put((byte) share2.getId(), tag);
                    share2.getMacKeys().put((byte) share1.getId(), key);
                } catch (InvalidKeyException e) {
                    throw new ImpossibleException("this cannot happen");
                }
            }
        }
        
        return rboshares;
    }

    @Override
    public byte[] reconstruct(Share[] shares) throws ReconstructionException {
        VSSShare[] rboshares = safeCast(shares); // we need access to it's inner fields
        Share[] valid = new Share[rboshares.length];
        int counter = 0;
        
        for (int i = 0; i < rboshares.length; i++) { // go through all shares
            int accepts = 0; // number of participants accepting i
            for (VSSShare rboshare: rboshares) { // go through all shares
                // TODO: split this up to make it more readable
                accepts += (mac.verifyMAC(rboshares[i].getShare().serialize(), rboshares[i].getMacs().get((byte) rboshare.getId()),
                                                        rboshare.getMacKeys().get((byte) rboshares[i].getId()))
                              ) ? 1 : 0; // verify the mac with the corresponding key for each share
            }
            
            if (accepts >= k) { // if there are at least k accepts, this share is counted as valid
                valid[counter++] = rboshares[i].getShare();
            }
        }
        
        if (counter >= k) {
            return sharing.reconstruct(Arrays.copyOfRange(valid, 0, counter));
        }
        
        throw new ReconstructionException(); // if there weren't enough valid shares
    }
    
    /**
     * Converts the Share[] to a RabinBenOrShare[] by casting each element individually.
     * 
     * @param shares the shares to cast
     * @return the given Share[] as RabinBenOrShare[]
     * @throws ClassCastException if the Share[] did not (only) contain RabinBenOrShares
     */
    private VSSShare[] safeCast(Share[] shares) {
        VSSShare[] rboshares = new VSSShare[shares.length];
        
        for (int i = 0; i < shares.length; i++) {
            rboshares[i] = (VSSShare) shares[i];
        }
        
        return rboshares;
    }
}
