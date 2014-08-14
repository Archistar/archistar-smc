package at.archistar.crypto;

import at.archistar.crypto.data.ShamirShare;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.decode.ErasureDecoder;
import at.archistar.crypto.decode.PolySolver;
import at.archistar.crypto.exceptions.ReconstructionException;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.math.GF256Polynomial;
import at.archistar.crypto.random.RandomSource;
import at.archistar.helper.ByteUtils;
import at.archistar.helper.ShareHelper;

/**
 * <p>This class implements the <i>Perfect-Secret-Sharing</i>-scheme (PSS) developed by Adi Shamir.</p>
 * 
 * <p>For a detailed description of the scheme, 
 * see: <a href='http://en.wikipedia.org/wiki/Shamir's_Secret_Sharing'>http://en.wikipedia.org/wiki/Shamir's_Secret_Sharing</a></p>
 * 
 * @author Elias Frantar <i>(code rewritten, documentation added)</i>
 * @author Andreas Happe <andreashappe@snikt.net>
 * @author Fehrenbach Franca-Sofia
 * @author Thomas Loruenser <thomas.loruenser@ait.ac.at>
 * 
 * @version 2014-7-25
 */
public class ShamirPSS extends SecretSharing {
    private final RandomSource rng;
    private final PolySolver solver;
    
    /**
     * Constructor
     * <p>(applying {@link ErasureDecoder} as default reconstruction algorithm)</p>
     * 
     * @param n the number of shares to create
     * @param k the minimum number of shares required for reconstruction
     * @param rng the source of randomness to use for generating the coefficients
     * @throws WeakSecurityException thrown if this scheme is not secure enough for the given parameters
     */
    public ShamirPSS(int n, int k, RandomSource rng) throws WeakSecurityException {
        this(n, k, rng, new ErasureDecoder());
    }
    /**
     * Constructor
     * 
     * @param n the number of shares to create
     * @param k the minimum number of shares required for reconstruction
     * @param rng the source of randomness to use for generating the coefficients
     * @param solver the solving algorithm to use for reconstructing the secret
     * @throws WeakSecurityException thrown if this scheme is not secure enough for the given parameters
     */
    public ShamirPSS(int n, int k, RandomSource rng, PolySolver solver) throws WeakSecurityException {
        super(n, k);
        
        this.rng = rng;
        this.solver = solver;
    }

    @Override
    public Share[] share(byte[] data) {
        ShamirShare shares[] = ShareHelper.createShamirShares(n, data.length);

        /* calculate the x and y values for the shares */
        for (int i = 0; i < data.length; i++) {
            GF256Polynomial poly = createShamirPolynomial(ByteUtils.toUnsignedByte(data[i]), k-1); // generate a new random polynomial
            
            for (ShamirShare share : shares) { // evaluate the x-values at the polynomial
                share.getY()[i] = (byte) poly.evaluateAt(share.getId());
            }
        }

        return shares;
    }

    @Override
    public byte[] reconstruct(Share[] shares) throws ReconstructionException {
        if (!validateShareCount(shares.length, k)) {
            throw new ReconstructionException();
        }
        
        try {
            ShamirShare[] sshares = safeCast(shares); // we need access to the inner fields
            
            byte[] result = new byte[sshares[0].getY().length];
            int[] xVals = ShareHelper.extractXVals(sshares);
            
            solver.prepare(xVals);
            
            for (int i = 0; i < result.length; i++) { // reconstruct all individual parts of the secret
                int[] yVals = ShareHelper.extractYVals(sshares, i);
                
                result[i] = (byte) solver.solve(yVals)[0];
            }   
            
            return result;
        } catch (Exception e) {
            throw new ReconstructionException();
        }
    }
    
    /**
     * Creates a new polynomial for Shamir-Secret-Sharing.<br>
     * In other words a polynomials with <i>degree</i> random coefficients and secret as the constant coefficient.
     * 
     * @param secret the secret to share (the constant coefficient)
     * @param degree the degree of the polynomial (number of random coefficients, must be <i>k</i>)
     * @return a random polynomial with the specified parameters ready for sharing the secret
     */
    private GF256Polynomial createShamirPolynomial(int secret, int degree) {
        int[] coeffs = new int[degree + 1];
        
        coeffs[0] = secret;
        
        for (int i = 1; i <= degree; i++) {
            coeffs[i] = rng.generateByte();
        }
        
        return new GF256Polynomial(coeffs);
    }

    /**
     * Converts the Share[] to a ShamirShare[] by casting each element individually.
     * 
     * @param shares the shares to cast
     * @return the given Share[] as ShamirShare[]
     * @throws ClassCastException if the Share[] did not (only) contain ShamirShares
     */
    private ShamirShare[] safeCast(Share[] shares) {
        ShamirShare[] sshares = new ShamirShare[shares.length];
        
        for (int i = 0; i < shares.length; i++) {
            sshares[i] = (ShamirShare) shares[i];
        }
        
        return sshares;
    }
}
