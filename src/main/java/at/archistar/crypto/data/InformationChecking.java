package at.archistar.crypto.data;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import at.archistar.helper.ImpossibleException;

/**
 * creates and verifies MACs for given shares.
 *
 * @author Andreas Happe <andreashappe@snikt.net>
 * @author Fehrenbach Franca-Sofia
 */
public class InformationChecking {

    private final MacHelper macHelper;

    public InformationChecking(MacHelper mac) {
        this.macHelper = mac;
    }

    public void addMacs(Share[] shares, String algorithm)
            throws InvalidKeyException, NoSuchAlgorithmException {

        //If there are no keys (no crypted shares) calculate the MAC of the content
        for (int i = 0; i < shares.length; i++) {
            //Calculate n-1 macs
            for (int j = 0; j < shares.length; j++) {
                if (i != j) {
                    byte[] key = macHelper.getKeyForHash();
                    byte[] mac = macHelper.getHash(key, shares[i].xValue, shares[i].yValues, shares[i].key);

                    //Put the MAC in share i and the key in share j
                    shares[i].macs.put(shares[j].xValue, mac);
                    shares[j].keys.put(shares[i].xValue, key);
                }
            }
        }
    }

    public boolean checkMacs(String algorithm, Share[] shares) {
        boolean failed = false;

        for (int i = 0; i < shares.length; i++) {
            for (int j = 0; j < shares.length; j++) {
                if (i != j) {
                    byte[] key = shares[j].keys.get(shares[i].xValue);

                    try {
                        byte[] mac = macHelper.getHash(key, shares[i].xValue, shares[i].yValues, shares[i].key);
                        byte[] old = shares[i].macs.get(shares[j].xValue);

                        if (Arrays.equals(mac, old)) {
                            shares[i].verificationCounter++;
                        } else {
                            failed = true;
                        }
                    } catch (InvalidKeyException e) {
                        throw new ImpossibleException(e);
                    } catch (NoSuchAlgorithmException e) {
                        throw new ImpossibleException(e);
                    }
                }
            }
        }

        return !failed;
    }
}
