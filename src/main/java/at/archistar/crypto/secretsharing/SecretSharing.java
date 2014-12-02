package at.archistar.crypto.secretsharing;

import at.archistar.crypto.data.Share;
import at.archistar.crypto.exceptions.ReconstructionException;

/**
 * Basic interface for secret sharing
 * 
 * @author andy
 */
interface SecretSharing {
    
    /**
     * Creates <i>n</i> secret shares for the given data where <i>k</i> shares are required for reconstruction. 
     * (n, k should have been previously initialized)
     * @param data the data to share secretly
     * @return the n different secret shares for the given data
     */
    Share[] share(byte[] data);
    
    /**
     * Attempts to reconstruct the secret from the given shares.<br>
     * This will fail if there are fewer than k (previously initialized) valid shares.
     * 
     * @param shares the shares to reconstruct the secret from
     * @return the reconstructed secret
     * @throws ReconstructionException thrown if the reconstruction failed
     */
    byte[] reconstruct(Share[] shares) throws ReconstructionException;
    
    int getN();
    
    int getK();
}

