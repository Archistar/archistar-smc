package at.archistar.crypto;

import java.security.GeneralSecurityException;

import at.archistar.crypto.data.InformationChecking;
import at.archistar.crypto.data.MacSha512;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.exceptions.ReconstructionException;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.random.RandomSource;

/**
 * @author Andreas Happe <andreashappe@snikt.net>
 * @author Thomas Loruenser <thomas.loruenser@ait.ac.at>
 */
public class RabinBenOrRSS implements SecretSharing {

    private final SecretSharing secretSharer;

    private final InformationChecking ic;

    private final int k;

    public RabinBenOrRSS(int n, int k, RandomSource rng, SecretSharing secretSharer) {
        this.k = k;
        this.secretSharer = secretSharer;
        this.ic = new InformationChecking(new MacSha512(rng));
    }

    @Override
    public Share[] share(byte[] data) throws WeakSecurityException,
            GeneralSecurityException {

        Share[] shares = secretSharer.share(data);
        ic.addMacs(shares, "HMacSHA512");
        return shares;
    }

    @Override
    public byte[] reconstruct(Share[] shares) throws ReconstructionException, GeneralSecurityException {

        ic.checkMacs("HMacSHA512", shares);

        int accepted = 0;
        for (Share s : shares) {
            if (s.verificationCounter >= (k - 1)) {
                s.accepted = true;
                accepted++;
            }
        }

        if (accepted >= k) {
            /* create a new array with only accepted shares */
            Share[] acceptedShares = new Share[accepted];
            for (int i = 0, k = 0; i < shares.length && k < accepted; i++) {
                acceptedShares[k++] = shares[i];
            }

            return secretSharer.reconstruct(acceptedShares);
        } else {
        	throw new ReconstructionException();
        }
    }
}
