package at.archistar.crypto.mac;

import at.archistar.crypto.informationchecking.CevallosUSRSS;
import java.security.NoSuchAlgorithmException;

/**
 * This is just part of a proof-of-concept of a key-shortener used for an
 * accurate implementation of the Cevallos-Scheme
 */
public class BCShortenedMacHelperFactory {
    /**
     * create a new mac helper
     * 
     * @param t ???
     * @param dataLength the wished-for mac length
     * @return the to-be-used mac
     * @throws NoSuchAlgorithmException should not happen
     */
    public static BCShortenedMacHelper create(int t, int dataLength) throws NoSuchAlgorithmException {
        return new BCShortenedMacHelper(new BCPoly1305MacHelper(), CevallosUSRSS.computeTagLength(dataLength, t, CevallosUSRSS.E));
    }
}
