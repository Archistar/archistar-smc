package at.archistar.crypto;

import at.archistar.crypto.data.ReconstructionResult;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.secretsharing.ReconstructionException;

/**
 * <p>This is the preferred interface for users of archistar-smc. Its implementations
 * combine all needed parts (secret-sharing, information-checking, decoder, etc.)
 * into usable crypto engines.</p>
 *
 * <p>Secret-sharing (or secret-splitting) algorithms distribute secrets between
 * <i>n</i> participants in such a way, that the original secret can only be
 * reconstructed if a minimum amount of participants offer their shares. If
 * fewer than this limit (which will be called <i>k</i> within archistar-smc)
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
 *
 * <p>To reconstruct only the missing shares out of an incomplete set, a special
 * method <i>recover</i> is provided. However, if it is used with Information Checking,
 * it is not possible to recover shares without changing the other shares (because if
 * a shares goes is lost, the keys used to generate the IC MACs of the other shares are
 * lost, too, and cannot be recovered; therefore they have to be regenerated and used
 * to generate new MACs, so the existing shares are changed); in this case, the method
 * will return a full set of shares</p>
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
     *
     * @param shares the split up data (should be a minimum of k shares)
     * @param start the starting position relative to the original data
     * @return a part of the original data
     */
    ReconstructionResult reconstructPartial(Share[] shares, long start);

    /**
     * recover missing shares
     *
     * note: this method will return all the shares that have to be
     * written out, which - depending on the algorithm used - may be only
     * the missing shares, but can (in case of PSS) also be the full set
     * of <i>n</i> shares
     *
     * @param shares the shares from which to recover
     * @return the recovered/changed shares
     */
    Share[] recover(Share[] shares) throws ReconstructionException;
}
