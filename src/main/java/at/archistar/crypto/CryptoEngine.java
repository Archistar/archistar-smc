package at.archistar.crypto;

import at.archistar.crypto.data.Share;
import at.archistar.crypto.exceptions.ReconstructionException;
import at.archistar.crypto.exceptions.WeakSecurityException;

/**
 * This is the preferred interface for users of archistar-smc. It's implementations
 * combine all needed parts (secret-sharing, information-checking, decoder, etc.)
 * into usable crypto engines.
 */
public interface CryptoEngine {
    
    public abstract Share[] share(byte[] data) throws WeakSecurityException;

    public abstract byte[] reconstruct(Share[] shares) throws ReconstructionException;
}
