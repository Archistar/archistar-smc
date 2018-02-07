package at.archistar.crypto.secretsharing;

import at.archistar.crypto.data.InvalidParametersException;
import at.archistar.crypto.data.RabinShare;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.math.gf256.GF256;

import java.util.stream.IntStream;

/**
 * <p>This class implements Rabin IDS (aka Reed-Solomon Code).</p>
 *
 * <p>Note: this scheme does not provide security but is rather used for quickly
 * distributing data that is not sensitive (or encrypted through other means).</p>
 *
 * <p>This implementation utilizes GeometricSecretSharing to obtain most of this
 * algorithm's implementation -- it's main addition is the encoding/decoding of
 * secrets into the equations coefficients ([a_0 .. a_k] in GeometricSecretSharing's
 * documentation). Rabin evenly distributes the original data between shares --
 * thus a0..a_k is just filled in with the original data.</p>
 *
 * <p>For a detailed description of this scheme, see:
 * <a href='http://en.wikipedia.org/wiki/Reed–Solomon_error_correction'>http://en.wikipedia.org/wiki/Reed–Solomon_error_correction</a></p>
 */
public class RabinIDS extends GeometricSecretSharing {

    /**
     * Constructor
     *
     * @param n the number of shares to create
     * @param k the minimum number of shares required for reconstruction
     * @param decoderFactory the solving algorithm to use for reconstructing the secret
     * @throws WeakSecurityException thrown if this scheme is not secure enough for the given parameters
     */
    public RabinIDS(int n, int k, DecoderFactory decoderFactory) throws WeakSecurityException {
        super(n, k, decoderFactory);
    }

    @Override
    public String toString() {
        return "RabinIDS(" + n + "/" + k + ")";
    }

    @Override
    protected int decodeData(int[] encoded, int originalLength, byte[] result, int offset) {
        for (int j = encoded.length - 1; j >= 0 && offset < originalLength; j--) {
            result[offset++] = (byte) encoded[encoded.length - 1 - j];
        }
        return offset;
    }

    @Override
    protected RabinShare[] createShares(int[] xValues, byte[][] results, int originalLength) throws InvalidParametersException {
        RabinShare shares[] = new RabinShare[n];

        for (int i = 0; i < n; i++) {
            shares[i] = new RabinShare((byte) xValues[i], results[i], originalLength);
        }

        return shares;
    }

    @Override
    protected int encodedSizeFor(int length) {
        if (length % k == 0) {
            return length / k;
        } else {
            return length / k + 1;
        }
    }

    @Override
    public void share(byte[][] output, byte[] data) {
        share(output, data, IntStream.range(0, n));
    }

    private void share(byte[][] output, byte[] data, IntStream range) {
        range.parallel().forEach(
                x -> {
                    int[] mul = mulTables[x];
                    byte[] out = output[x];
                    for (int i = k - 1; i < data.length; i += k) {
                        int res = data[i] & 0xff;
                        for (int y = 1; y < k; y++) {
                            res = GF256.add(data[i - y] & 0xff, mul[res]);
                        }
                        out[i / k] = (byte) res;
                    }
                    if (data.length % k != 0) {
                        int res = data[data.length - 1] & 0xff;
                        for (int y = data.length - 2; y >= data.length - data.length % k; y--) {
                            res = GF256.add(data[y] & 0xff, mul[res]);
                        }
                        out[data.length / k] = (byte) res;
                    }
                }
        );
    }

    @Override
    public RabinShare[] recover(Share[] shares) throws ReconstructionException {
        byte[] missing = determineMissingShares(shares);
        int len = shares[0].getYValues().length;
        int olen = shares[0].getOriginalLength();
        byte[] reconstructed = reconstruct(shares);
        byte[][] recovered = new byte[n][];
        for (byte b : missing) {
            recovered[b - 1] = new byte[len];
        }

        IntStream stream = IntStream.range(0, missing.length)
                .map(i -> missing[i] - 1);

        share(recovered, reconstructed, stream);

        RabinShare[] res = new RabinShare[missing.length];

        for (int i = 0; i < missing.length; i++) {
            try {
                res[i] = new RabinShare(missing[i], recovered[missing[i] - 1], olen);
            } catch (InvalidParametersException e) {
                throw new ReconstructionException(e.toString());
            }
        }

        return res;
    }
}
