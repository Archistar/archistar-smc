package at.archistar.crypto.secretsharing;

import at.archistar.crypto.CryptoEngine;
import at.archistar.crypto.data.Share;

/**
 * <p>Basic application programming interface for secret sharing.</p>
 * 
 * <p>Secret-sharing (or secret-splitting) algorithms distribute secrets between
 * n participants in such a way, that the original secret can only be
 * reconstructed if a minimum amount of participants offer their shares. If
 * fewer than this limit (which will be called k within archistar-smc)
 * participants offer their share, the original data cannot be reconstructed.</p>
 * 
 * <p>This interface offers a simplified view to secret sharing, the two main
 * operations are: share for creating shares and reconstruct for reconstructing
 * the original secret from the given shares.</p>
 */
public interface SecretSharing extends CryptoEngine {
    
    /**
     * Creates <i>n</i> secret shares for the given data where <i>k</i> shares are required for reconstruction. 
     * @param data the data to share secretly
     * @return the n different secret shares for the given data
     */
    @Override
    Share[] share(byte[] data);
    
    /**
     * Attempts to reconstruct the secret from the given shares.<br>
     * This will fail if there are fewer than k (previously initialized) valid shares.
     * 
     * @param shares the shares to reconstruct the secret from
     * @return the reconstructed secret
     * @throws ReconstructionException thrown if the reconstruction failed
     */
    @Override
    byte[] reconstruct(Share[] shares) throws ReconstructionException;
    
    /**
     * @return the created share count
     */
    int getN();
    
    /**
     * @return amount of shares needed for reconstruction
     */
    int getK();
}

