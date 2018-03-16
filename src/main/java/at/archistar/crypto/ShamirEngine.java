package at.archistar.crypto;

import at.archistar.crypto.data.ReconstructionResult;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.decode.ErasureDecoderFactory;
import at.archistar.crypto.random.BCDigestRandomSource;
import at.archistar.crypto.random.RandomSource;
import at.archistar.crypto.secretsharing.ReconstructionException;
import at.archistar.crypto.secretsharing.ShamirPSS;
import at.archistar.crypto.secretsharing.WeakSecurityException;

import java.util.Collections;

public class ShamirEngine implements CryptoEngine {

    private final int n;
    private final int k;
    private final ShamirPSS engine;

    public ShamirEngine(int n, int k) throws WeakSecurityException {
        this(n, k, new BCDigestRandomSource());
    }

    public ShamirEngine(int n, int k, RandomSource rng) throws WeakSecurityException {
        this.n = n;
        this.k = k;
        DecoderFactory decoderFactory = new ErasureDecoderFactory();
        engine = new ShamirPSS(n, k, rng, decoderFactory);
    }

    @Override
    public Share[] share(byte[] data) {
        return engine.share(data);
    }

    @Override
    public ReconstructionResult reconstruct(Share[] shares) {
        try {
            return new ReconstructionResult(engine.reconstruct(shares));
        } catch (ReconstructionException e) {
            return new ReconstructionResult(Collections.singletonList(e.toString()));
        }
    }

    @Override
    public ReconstructionResult reconstructPartial(Share[] shares, long start) {
        try {
            return new ReconstructionResult(engine.reconstructPartial(shares, start));
        } catch (ReconstructionException e) {
            return new ReconstructionResult(Collections.singletonList(e.toString()));
        }
    }

    @Override
    public Share[] recover(Share[] shares) throws ReconstructionException {
        return engine.recover(shares);
    }

    @Override
    public String toString() {
        return "Shamir(" + k + "/" + n + ")";
    }
}
