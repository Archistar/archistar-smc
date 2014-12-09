package at.archistar.crypto;

import at.archistar.crypto.data.Share;
import at.archistar.crypto.secretsharing.ReconstructionException;

/**
 * <p>This is the preferred interface for users of archistar-smc. It's implementations
 * combine all needed parts (secret-sharing, information-checking, decoder, etc.)
 * into usable crypto engines.</p>
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
public interface CryptoEngine {
    
    /**
     * split up data in shares
     * 
     * @param data the original data that should be split up
     * @return an array of shares
     */
    public Share[] share(byte[] data);

    /**
     * reconstruct the original data from given shares
     * 
     * @param shares the split up data (should be a minimum of k shares)
     * @return the original data
     * @throws ReconstructionException is thrown is reconstruction failed
     */
    public byte[] reconstruct(Share[] shares) throws ReconstructionException;
}
