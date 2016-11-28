package at.archistar.crypto.secretsharing;

import at.archistar.crypto.data.InvalidParametersException;
import at.archistar.crypto.data.KrawczykShare;
import at.archistar.crypto.data.Share;

import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.decode.ErasureDecoder;
import at.archistar.crypto.math.DynamicOutputEncoderConverter;
import at.archistar.crypto.math.EncodingConverter;
import at.archistar.crypto.math.GF;
import at.archistar.crypto.math.OutputEncoderConverter;
import at.archistar.crypto.math.StaticOutputEncoderConverter;
import at.archistar.crypto.math.gf257.GF257;
import at.archistar.crypto.random.RandomSource;
import at.archistar.crypto.symmetric.AESEncryptor;
import at.archistar.crypto.symmetric.AESGCMEncryptor;
import at.archistar.crypto.symmetric.Encryptor;

import java.io.IOException;
import java.security.GeneralSecurityException;

import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * <p>This class implements the Computational Secret Sharing scheme developed by Krawczyk.</p>
 *
 * <p>This is a hybrid scheme that combines classical symmetric encryption, ShamirPSS
 * and RabinIDS. The secret data is initially encrypted using an traditional
 * symmetric encryption scheme (i.e. AES, Salsa, ChaCha..). The resulting encoded
 * data is then distributed between participants with the fast but insecure
 * RabinIDS scheme. The key that was used during the encryption is split up using
 * the slow but secure ShamirPSS scheme and also distributed between participants.
 * The performance benefit arises from the fact that the encryption key is many
 * times smaller then the encrypted data -- the (computation- and storage-wise)
 * inefficient shamir-pss algorithm thus performs only on small amounts of data
 * while the faster performing and more space-efficient rabin-ids algorithm is
 * used for the encrypted (larger) data.</p>
 *
 * <p>For detailed information about this scheme, see:
 * http://courses.csail.mit.edu/6.857/2009/handouts/short-krawczyk.pdf</p>
 */
public class KrawczykCSS extends BaseSecretSharing {

    private final RandomSource rng;

    private final GeometricSecretSharing shamir;

    private final GeometricSecretSharing rs;

    private final Encryptor cryptor;

    private final GF gf;

    /**
     * Constructor
     * (Applying the default settings for the Shamir-RNG and the decoders: {@link SHA1PRNG} and {@link ErasureDecoder})
     *
     * @param n the number of shares
     * @param k the minimum number of shares required for reconstruction
     * @param rng the RandomSource to be used for the underlying Shamir-scheme
     * @param cryptor the to be used encryption algorithms
     * @throws WeakSecurityException thrown if this scheme is not secure for the given parameters
     */
    public KrawczykCSS(int n, int k, RandomSource rng,
                       Encryptor cryptor,
                       DecoderFactory decFactory, GF gf) throws WeakSecurityException {
        super(n, k);

        this.shamir = new ShamirPSS(n, k, rng, decFactory, gf);
        this.rs = new RabinIDS(n, k, decFactory, gf);
        this.cryptor = cryptor;
        this.rng = rng;
        this.gf = gf;
    }

    @Override
    public Share[] share(byte[] data) {
        try {
            if (data == null) {
                data = new byte[0];
            }
            /* encrypt the data */
            byte[] encKey = new byte[cryptor.getKeyLength()];
            this.rng.fillBytes(encKey);
            byte[] encSource = cryptor.encrypt(data, encKey);

            int baseDataLength = data.length;
            // block cyphers use 16 byte blocks and add an extra block at the end
            if (cryptor instanceof AESEncryptor || cryptor instanceof AESGCMEncryptor) {
                baseDataLength = ((data.length / 16) + 1) * 16;
            }
            int newDataLength = baseDataLength % k == 0 ? baseDataLength / k : (baseDataLength / k) + 1;

            /* share key and content */
            OutputEncoderConverter outputContent[] = new OutputEncoderConverter[n];
            OutputEncoderConverter outputKey[] = new OutputEncoderConverter[n];
            for (int i = 0; i < n; i++) {
                if (gf instanceof GF257) {
                    outputKey[i] = new DynamicOutputEncoderConverter(encKey.length, gf);
                    outputContent[i] = new DynamicOutputEncoderConverter(newDataLength, gf);
                } else {
                    outputKey[i] = new StaticOutputEncoderConverter(encKey.length);
                    outputContent[i] = new StaticOutputEncoderConverter(newDataLength);
                }
            }

            rs.share(outputContent, encSource);
            shamir.share(outputKey, encKey);

            //Generate a new array of encrypted shares
            Share[] kshares = new Share[n];
            for (int i = 0; i < kshares.length; i++) {
                kshares[i] = new KrawczykShare((byte) (i + 1), outputContent[i].getEncodedData(),
                        encSource.length, 1, outputKey[i].getEncodedData());

            }

            return kshares;
        } catch (GeneralSecurityException | InvalidCipherTextException | IOException | InvalidParametersException e) {
            // encryption should actually never fail
            throw new RuntimeException("impossible: sharing failed (" + e.getMessage() + ")");
        }
    }

    @SuppressWarnings("cyclomaticcomplexity")
    private byte[] reconstruct(Share[] shares, boolean partial) throws ReconstructionException {

        if (shares.length < k) {
            throw new ReconstructionException("too few shares");
        }

        for (Share s : shares) {
            if (!(s instanceof KrawczykShare)) {
                throw new ReconstructionException("Not all shares are Krawczyk shares");
            }
        }

        int originalLengthContent = shares[0].getOriginalLength();
        int originalLengthKey = ((KrawczykShare) shares[0]).getKey().length;
        for (Share s : shares) {
            if (s.getOriginalLength() != originalLengthContent) {
                throw new ReconstructionException("Shares have different original length");
            }
            if (((KrawczykShare) s).getKey().length != originalLengthKey) {
                throw new ReconstructionException("Shares have different key length");
            }
        }

        try {
            int[] xValues = GeometricSecretSharing.extractXVals(shares, k);
            EncodingConverter[] ecKey = new EncodingConverter[shares.length];
            EncodingConverter[] ecContent = new EncodingConverter[shares.length];
            for (int i = 0; i < shares.length; i++) {
                ecKey[i] = new EncodingConverter(((KrawczykShare) shares[i]).getKey(), gf);
                ecContent[i] = new EncodingConverter(shares[i].getYValues(), gf);
            }

            byte[] key = shamir.reconstruct(ecKey, xValues, originalLengthKey);
            byte[] encShare;
            if (partial) {
                int actualLengthContent = shares[0].getYValues().length;
                for (Share s : shares) {
                    if (s.getYValues().length != actualLengthContent) {
                        throw new ReconstructionException("Shares have different actual length");
                    }
                }
                int reconstructionLength = actualLengthContent % k == 0 ? actualLengthContent * k : actualLengthContent * (k - 1);
                encShare = rs.reconstruct(ecContent, xValues, reconstructionLength);
            } else {
                encShare = rs.reconstruct(ecContent, xValues, originalLengthContent);
            }

            return cryptor.decrypt(encShare, key);
        } catch (GeneralSecurityException | IOException | IllegalStateException | InvalidCipherTextException e) {
            // decryption should actually never fail
            throw new RuntimeException("impossible: reconstruction failed (" + e.getMessage() + ")");
        }
    }

    @Override
    public byte[] reconstruct(Share[] shares) throws ReconstructionException {
        return reconstruct(shares, false);
    }

    @Override
    public byte[] reconstructPartial(Share[] shares) throws ReconstructionException {
        if (cryptor instanceof AESEncryptor || cryptor instanceof AESGCMEncryptor) {
            throw new ReconstructionException("Partial reconstruction not possible with given cypher");
        }
        return reconstruct(shares, true);
    }

    @Override
    public String toString() {
        return "KrawczykCSS(" + n + "/" + k + ", " + cryptor + ")";
    }
}
