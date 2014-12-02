package at.archistar.crypto;

import at.archistar.crypto.data.SerializableShare;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.data.VSSShare;
import at.archistar.crypto.exceptions.ReconstructionException;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.informationchecking.InformationChecking;
import at.archistar.crypto.informationchecking.RabinBenOrRSS;
import at.archistar.crypto.secretsharing.BaseSecretSharing;
import java.io.IOException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author andy
 */
public abstract class AbstractICEngine implements CryptoEngine {

    private final BaseSecretSharing sharing;
    
    private final InformationChecking ic;
    
    public AbstractICEngine(BaseSecretSharing sharing, InformationChecking checking) {
        this.sharing = sharing;
        this.ic = checking;
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
