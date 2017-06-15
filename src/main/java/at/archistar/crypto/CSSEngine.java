package at.archistar.crypto;

import at.archistar.crypto.data.*;
import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.decode.ErasureDecoderFactory;
import at.archistar.crypto.random.BCDigestRandomSource;
import at.archistar.crypto.random.RandomSource;
import at.archistar.crypto.secretsharing.KrawczykCSS;
import at.archistar.crypto.secretsharing.ReconstructionException;
import at.archistar.crypto.secretsharing.WeakSecurityException;
import at.archistar.crypto.symmetric.ChaCha20Encryptor;
import at.archistar.crypto.symmetric.Encryptor;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.stream.Collectors;

/**
 * CryptoEngine for Computationally Secure Secret Sharing
 * (Krawczyk CSS + Fingerprinting)
 *
 * @author Andreas Happe <andreashappe@snikt.net>
 */
public class CSSEngine implements CryptoEngine {

    /** how many shares should be generated */
    private final int n;

    /** minimum amount of shares needed to reconstruct original data */
    private final int k;

    private final KrawczykCSS engine;

    private final MessageDigest digest;

    /**
     * initialize the crypto engine
     *
     * @param n total number of shares
     * @param k minimum count of shares needed to recreate the original data
     * @throws WeakSecurityException if the k/n selection is insecure
     */
    CSSEngine(int n, int k) throws WeakSecurityException {
        this(n, k, new BCDigestRandomSource());
    }

    /**
     * Create a new CSS Engine.
     *
     * @param n total number of shares
     * @param k minimum count of shares needed to recreate the original data
     * @param rng random number generator to be used
     * @throws WeakSecurityException if the k/n selection is insecure
     */
    CSSEngine(int n, int k, RandomSource rng) throws WeakSecurityException {
        this.n = n;
        this.k = k;
        DecoderFactory decoderFactory = new ErasureDecoderFactory();
        Encryptor cryptor = new ChaCha20Encryptor();
        this.engine = new KrawczykCSS(n, k, rng, cryptor, decoderFactory);
        try {
            this.digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    CSSEngine(int n, int k, RandomSource rng, byte[] key) throws WeakSecurityException, InvalidParametersException {
        this.n = n;
        this.k = k;
        DecoderFactory decoderFactory = new ErasureDecoderFactory();
        Encryptor cryptor = new ChaCha20Encryptor();
        this.engine = new KrawczykCSS(n, k, rng, cryptor, decoderFactory, key);
        try {
            this.digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public CSSShare[] share(byte[] data) {
        final KrawczykShare[] raw = engine.share(data);
        final CSSShare[] res = new CSSShare[n];
        final Map<Byte, byte[]> fingerprints = new HashMap<>();

        for (KrawczykShare share : raw) {
            fingerprints.put(share.getId(), digest.digest(share.getYValues()));
        }

        for (int i = 0; i < res.length; i++) {
            try {
                res[i] = new CSSShare(raw[i], fingerprints);
            } catch (InvalidParametersException e) {
                throw new RuntimeException("Should not be possible: " + e);
            }
        }

        return res;
    }

    @Override
    public ReconstructionResult reconstruct(Share[] shares) {
        if (!Arrays.stream(shares).allMatch(s -> s instanceof CSSShare)) {
            return new ReconstructionResult(Collections.singletonList("Not all shares are CSS Shares"));
        }
        Map<Boolean, List<CSSShare>> partitioned = Arrays.stream(shares)
                .map(s -> (CSSShare) s)
                .collect(Collectors.partitioningBy(
                        s -> Arrays.stream(shares)
                                .map(s0 -> (CSSShare) s0)
                                .filter(s0 -> Arrays.equals(
                                        digest.digest(s.getYValues()),
                                        (s0.getFingerprints().get(s.getId()))))
                                .count() >= k)
                );
        CSSShare[] valid = partitioned.get(Boolean.TRUE).toArray(new CSSShare[partitioned.get(Boolean.TRUE).size()]);
        List<String> errors = partitioned.get(Boolean.FALSE).stream()
                .map(s -> "Could not validate " + s).collect(Collectors.toList());
        try {
            return new ReconstructionResult(engine.reconstruct(valid), errors);
        } catch (ReconstructionException e) {
            errors.add(e.getMessage());
            return new ReconstructionResult(errors);
        }
    }

    @Override
    public ReconstructionResult reconstructPartial(Share[] shares, long start) {
        if (!Arrays.stream(shares).allMatch(s -> s instanceof CSSShare)) {
            return new ReconstructionResult(Collections.singletonList("Not all shares are CSS Shares"));
        }
        String warning = "*** WARNING: Partial reconstruction -- no fingerprints are checked!";
        System.err.println(warning);
        try {
            return new ReconstructionResult(engine.reconstructPartial(shares, start),
                    Collections.singletonList(warning));
        } catch (ReconstructionException e) {
            return new ReconstructionResult(Collections.singletonList(e.getMessage()));
        }
    }

    @Override
    public String toString() {
        return "CSS(" + k + "/" + n + ")";
    }
}
