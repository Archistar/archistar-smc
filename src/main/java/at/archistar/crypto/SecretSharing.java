package at.archistar.crypto;

import java.security.GeneralSecurityException;

import at.archistar.crypto.data.Share;


public interface SecretSharing {

	Share[] share(byte[] data) throws WeakSecurityException, GeneralSecurityException;
		
	byte[] reconstruct(Share[] shares) throws GeneralSecurityException;
}