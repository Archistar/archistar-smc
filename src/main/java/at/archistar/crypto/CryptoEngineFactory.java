package at.archistar.crypto;

import at.archistar.crypto.data.InvalidParametersException;
import at.archistar.crypto.random.RandomSource;
import at.archistar.crypto.secretsharing.WeakSecurityException;

import java.security.NoSuchAlgorithmException;

/**
 * @author florian
 */
public class CryptoEngineFactory {

    /**
     * Computational Secure Secret Sharing with Fingerprinting
     */
    public static CSSEngine getCSSEngine(int n, int k) throws WeakSecurityException {
        return new CSSEngine(n, k);
    }

    /**
     * Computational Secure Secret Sharing with Fingerprinting (custom Random Number Generator)
     */
    public static CSSEngine getCSSEngine(int n, int k, RandomSource rng) throws WeakSecurityException {
        return new CSSEngine(n, k, rng);
    }

    /**
     * Computational Secure Secret Sharing with Fingerprinting (custom Random Number Generator)
     * <p>
     * This variant will use the given key to encrypt all generated keys before secret-sharing
     */
    public static CSSEngine getCSSEngine(int n, int k, RandomSource rng, byte[] key) throws WeakSecurityException, InvalidParametersException {
        return new CSSEngine(n, k, rng, key);
    }

    /**
     * Perfect Secret Sharing with Information Checking
     */
    public static PSSEngine getPSSEngine(int n, int k) throws WeakSecurityException, NoSuchAlgorithmException {
        return new PSSEngine(n, k);
    }

    /**
     * Perfect Secret Sharing with Information Checking (custom Random Number Generator)
     */
    public static PSSEngine getPSSEngine(int n, int k, RandomSource rng) throws WeakSecurityException, NoSuchAlgorithmException {
        return new PSSEngine(n, k, rng);
    }
}
