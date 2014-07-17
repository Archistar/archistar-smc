package at.archistar.crypto;

import at.archistar.crypto.data.Share;
import at.archistar.crypto.decode.ErasureDecoder;
import at.archistar.crypto.decode.PolySolver;
import at.archistar.crypto.exceptions.ReconstructionException;

/**
 * <p>This is the abstract base class for all Secret-Sharing algorithms.</p>
 * 
 * <p><i>Secret Sharing</i> means splitting up some secret (for example a message) in <i>n</i> pieces such that any number of
 * at least <i>k</i> pieces can reconstruct the secret, but <i>k - 1</i> pieces yield absolutely no information about the
 * secret.</p>
 * 
 * For detailed information, see: 
 * <a href="http://en.wikipedia.org/wiki/Secret_sharing">http://en.wikipedia.org/wiki/Secret_sharing</a>
 * 
 * @author Elias Frantar
 * @version 2014-7-14
 */
public abstract class SecretSharing {
	protected int n; // number of shares
	protected int k; // number of shares required for reconstruction
	
	protected PolySolver solver; // solver for reconstructing the polynomial
	
	/**
	 * Creates <i>n</i> secret shares for the given data where <i>k</i> shares are required for reconstruction. 
	 * (n, k should have been previously initialized)
	 * @param data the data to share secretly
	 * @return the n different secret shares for the given data
	 */
    public abstract Share[] share(byte[] data);
    
    /**
     * Attempts to reconstruct the secret from the given shares.<br>
     * This will fail if there are fewer than k (previously initialized) valid shares.
     * 
     * @param shares the shares to reconstruct the secret from
     * @return the reconstructed secret
     * @throws ReconstructionException thrown if the reconstruction failed
     */
    public abstract byte[] reconstruct(Share[] shares) throws ReconstructionException;
    
    
    /* Setters for optionally exchangeable fields */
    
    /**
	 * <p>Sets the reconstruction algorithm, which will be used for reconstructing the secret.</p>
	 * 
	 * <p><b>NOTE:</b> the default one is: {@link ErasureDecoder}/p>
	 * @param solver the solver to use for reconstructing the polynomial
	 */
	public void setSolver(PolySolver solver) { this.solver = solver; }
	
	
    /* only Getters; these fields should be immutable */
    public int getN() { return n; }
    public int getK() { return k; }
}