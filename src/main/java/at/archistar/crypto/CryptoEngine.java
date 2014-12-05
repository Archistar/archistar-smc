package at.archistar.crypto;

import at.archistar.crypto.data.Share;
import at.archistar.crypto.secretsharing.ReconstructionException;

/**
 * This is the preferred interface for users of archistar-smc. It's implementations
 * combine all needed parts (secret-sharing, information-checking, decoder, etc.)
 * into usable crypto engines.
 */
public interface CryptoEngine {
    
    /**
     * split up data in shares
     * 
     * @param data the original data that should be split up
     * @return an array of shares
     */
    public abstract Share[] share(byte[] data);

    /**
     * reconstruct the original data from given shares
     * 
     * @param shares the split up data (should be a minimum of k shares)
     * @return the original data
     * @throws ReconstructionException is thrown is reconstruction failed
     */
    public abstract byte[] reconstruct(Share[] shares) throws ReconstructionException;
}
