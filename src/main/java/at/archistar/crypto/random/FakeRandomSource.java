package at.archistar.crypto.random;

/**
 * Fake Random numbers for test cases -- this allows us to
 * easily compare results within test cases
 * 
 * @author Andreas Happe <andreashappe@snikt.net>
 */
public class FakeRandomSource implements RandomSource {
	@Override
	public int generateByte() {
		return 4;
	}
}
