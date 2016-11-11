package at.archistar.crypto.secretsharing;

import at.archistar.crypto.data.InvalidParametersException;
import at.archistar.crypto.data.NTTShamirShare;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.math.GFFactory;
import at.archistar.crypto.math.OutputEncoderConverter;
import at.archistar.crypto.math.ntt.AbstractNTT;
import at.archistar.crypto.random.RandomSource;

/**
 * Perform shamir's secret sharing using an NTT operation
 */
public class NTTShamirPSS extends NTTSecretSharing {

    private final RandomSource rng;

    /**
     * create a new shamir's secret sharing instance
     *
     * @param n how many shares should be created
     * @param k how many shares need to be present to reconstruct the data
     * @param generator the generator used for the ntt operation
     * @param factory factory for mathematical operations
     * @param rng the random number generator to be used
     * @param ntt the ntt operation that will be sued
     * @param decoderFactory encoder used for reconstructing data
     */
    public NTTShamirPSS(int n, int k, int generator, GFFactory factory,
                        RandomSource rng, AbstractNTT ntt,
                        DecoderFactory decoderFactory)
            throws WeakSecurityException {

        super(n, k, generator, factory, ntt, decoderFactory);

        this.rng = rng;

        /** how much (in bytes) can we fit per share (n shares must fit into
         * a NTTBlock)
         */
        shareSize = nttBlockLength / n;
        dataPerNTT = nttBlockLength / n * 1;
    }

    @Override
    protected int[] encodeData(int tmp[], int[] data, int offset, int length) {
        System.arraycopy(data, offset, tmp, 0, length);

        /* (k-1) -- shamir uses 1 byte secret and (k-1) byte randomness */
        int[] random = new int[length * (k - 1)];
        rng.fillBytesAsInts(random);

        System.arraycopy(random, 0, tmp, dataPerNTT, random.length);

        return tmp;
    }

    @Override
    int extractShareCount(Share[] shares) throws ReconstructionException {
        for (Share s : shares) {
            if (!(s instanceof NTTShamirShare)) {
                throw new ReconstructionException("Not all shares are NTT Shamir shares");
            }
        }
        int shareCount = ((NTTShamirShare) shares[0]).getNttShareSize();
        for (Share s : shares) {
            if (((NTTShamirShare) s).getNttShareSize() != shareCount) {
                throw new ReconstructionException("Shares have different original length");
            }
        }
        return shareCount;
    }

    @Override
    public String toString() {
        return "NTTShamirPSS(" + n + "/" + k + ", NTTLength: " + nttBlockLength + ")";
    }

    @Override
    public Share[] share(byte[] data) {
        int[] dataInt = new int[data.length];
        for (int i = 0; i < data.length; i++) {
            dataInt[i] = (data[i] < 0) ? data[i] + 256 : data[i];
        }

        OutputEncoderConverter[] encoded = encode(dataInt);

        Share shares[] = new Share[n];
        for (int j = 0; j < n; j++) {
            try {
                shares[j] = new NTTShamirShare((byte) (j + 1), encoded[j].getEncodedData(), data.length, shareSize);
            } catch (InvalidParametersException e) {
                throw new RuntimeException("impossible: cannot happen");
            }
        }
        return shares;
    }
}
