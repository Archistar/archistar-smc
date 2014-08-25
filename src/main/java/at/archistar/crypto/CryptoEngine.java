package at.archistar.crypto;

import at.archistar.crypto.data.Share;
import at.archistar.crypto.exceptions.ReconstructionException;

/**
 * This is the preferred interface for users of archistar-smc. It's implementations
 * combine all needed parts (secret-sharing, information-checking, decoder, etc.)
 * into usable crypto engines.
 */
public interface CryptoEngine {
    
    public abstract Share[] share(byte[] data);

    public abstract byte[] reconstruct(Share[] shares) throws ReconstructionException;
}
