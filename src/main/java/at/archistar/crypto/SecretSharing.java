package at.archistar.crypto;

import java.security.GeneralSecurityException;

import at.archistar.crypto.data.Share;
import at.archistar.crypto.exceptions.ReconstructionException;
import at.archistar.crypto.exceptions.WeakSecurityException;

public interface SecretSharing {

	/* TODO: When should a GeneralSecurityException occur? Do we even need it? */
	
    Share[] share(byte[] data) throws WeakSecurityException, GeneralSecurityException;

    byte[] reconstruct(Share[] shares) throws ReconstructionException, GeneralSecurityException;
}
