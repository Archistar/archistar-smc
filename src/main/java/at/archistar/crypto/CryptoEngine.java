package at.archistar.crypto;

import at.archistar.crypto.data.ReconstructionResult;
import at.archistar.crypto.data.Share;

/**
 * <p>This is the preferred interface for users of archistar-smc. Its implementations
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
 *
 * <p>There is also the possibility of trying to reconstruct partial shares. This
 * is useful to access specific parts of the shared data.
 * However, this is not possible when using a Krawczyk secret-sharing scheme with
 * a cypher that tries to authenticate the data. Any attempt to reconstruct such a
 * partial share will immediately throw a ReconstructionException. Also, be aware
 * that the different secret-sharing schemes may impose different constraints on the
 * alignment of the partial shares, and may also return data that has to be truncated
 * on one or both ends.</p>
 */
public interface CryptoEngine {

    /**
     * split up data in shares
     *
     * @param data the original data that should be split up
     * @return an array of shares
     */
    Share[] share(byte[] data);

    /**
     * reconstruct the original data from given shares
     *
     * @param shares the split up data (should be a minimum of k shares)
     * @return the original data
     */
    ReconstructionResult reconstruct(Share[] shares);

    /**
     * reconstruct a part of the original data from the given partial shares

     * @param shares the split up data (should be a minimum of k shares)
     * @param start the starting position relative to the original data
     * @return a part of the original data
     */
    ReconstructionResult reconstructPartial(Share[] shares, long start);
}
