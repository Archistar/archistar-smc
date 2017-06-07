package at.archistar.crypto;

import at.archistar.crypto.random.RandomSource;
import at.archistar.crypto.secretsharing.WeakSecurityException;

import java.security.NoSuchAlgorithmException;

/**
 * @author florian
 */
public class CryptoEngineFactory {

    public static CSSEngine getCSSEngine(int n, int k) throws WeakSecurityException {
        return new CSSEngine(n, k);
    }

    public static CSSEngine getCSSEngine(int n, int k, RandomSource rng) throws WeakSecurityException {
        return new CSSEngine(n, k, rng);
    }

    public static PSSEngine getPSSEngine(int n, int k) throws WeakSecurityException, NoSuchAlgorithmException {
        return new PSSEngine(n, k);
    }

    public static PSSEngine getPSSEngine(int n, int k, RandomSource rng) throws WeakSecurityException, NoSuchAlgorithmException {
        return new PSSEngine(n, k, rng);
    }
}
