package at.archistar.crypto.secretsharing;

import at.archistar.crypto.data.InvalidParametersException;
import at.archistar.crypto.data.NTTRabinShare;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.math.GFFactory;
import at.archistar.crypto.math.OutputEncoderConverter;
import at.archistar.crypto.math.ntt.AbstractNTT;

/**
 * perform reed-solomon coding using NTT
 */
public class NTTRabinIDS extends NTTSecretSharing {

    /**
     * create a new NTTRabinIDS secret-sharing
     *
     * @param n amount of shares to be generated
     * @param k minimum amount of shares for reconstruction
     * @param generator the generator
     * @param factory the field within which we're working (should be GF257 for now)
     * @param ntt the ntt used for computation (shoudl be |gf|+1)
     * @param decoderFactory the decoder that will be used for the reconstruction step
     */
    public NTTRabinIDS(int n, int k, int generator,
                       GFFactory factory,
                       AbstractNTT ntt,
                       DecoderFactory decoderFactory) throws WeakSecurityException {

        super(n, k, generator, factory, ntt, decoderFactory);

        shareSize = nttBlockLength / n;
        dataPerNTT = nttBlockLength / n * k;
    }

    @Override
    protected int[] encodeData(int tmp[], int[] data, int offset, int length) {
        System.arraycopy(data, offset, tmp, 0, length);
        return tmp;
    }

    /**
     * @return human-readable description of this secret-sharing scheme
     */
    @Override
    public String toString() {
        return "NTTRabinIDS(" + n + "/" + k + ", NTTLength: " + nttBlockLength + ")";
    }

    @Override
    public Share[] share(byte[] data) {
        if (data == null) {
            data = new byte[0];
        }
        int[] dataInt = new int[data.length];
        for (int i = 0; i < data.length; i++) {
            dataInt[i] = (data[i] < 0) ? data[i] + 256 : data[i];
        }

        OutputEncoderConverter[] encoded = encode(dataInt);

        Share shares[] = new Share[n];
        for (int j = 0; j < n; j++) {
            try {
                shares[j] = new NTTRabinShare((byte) (j + 1), encoded[j].getEncodedData(), data.length, shareSize);
            } catch (InvalidParametersException e) {
                throw new RuntimeException("impossible: cannot happen");
            }
        }
        return shares;
    }

    int extractShareCount(Share[] shares) throws ReconstructionException {
        for (Share s : shares) {
            if (!(s instanceof NTTRabinShare)) {
                throw new ReconstructionException("Not all shares are NTT Rabin shares");
            }
        }
        int shareCount = ((NTTRabinShare) shares[0]).getNttShareSize();
        for (Share s : shares) {
            if (((NTTRabinShare) s).getNttShareSize() != shareCount) {
                throw new ReconstructionException("Shares have different original length");
            }
        }
        return shareCount;
    }
}
