package at.archistar.crypto.mac;

import at.archistar.crypto.informationchecking.CevallosUSRSS;
import java.security.NoSuchAlgorithmException;

/**
 * This is just part of a proof-of-concept of a key-shortener used for an
 * accurate implementation of the Cevallos-Scheme
 * 
 * @author andy
 */
public class BCShortenedMacHelperFactory {
    public static BCShortenedMacHelper create(int t, int dataLength) throws NoSuchAlgorithmException {
        return new BCShortenedMacHelper(new BCPoly1305MacHelper(), CevallosUSRSS.computeTagLength(dataLength, t, CevallosUSRSS.E));
    }
}
