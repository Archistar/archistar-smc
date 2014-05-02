package at.archistar.crypto.data;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * We want to add hashes to created shares to make them resistent in case of
 * errors.
 *
 * @author Andreas Happe <andreashappe@snikt.net>
 */
public interface MacHelper {

    public byte[] getKeyForHash() throws NoSuchAlgorithmException;

    public byte[] getHash(byte[] key, int xValue, byte yValues[], byte[] keys) throws InvalidKeyException, NoSuchAlgorithmException;
}
