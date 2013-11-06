package at.archistar.crypto.random;

/**
 * Some algorithms need a random source. This interface allows
 * easy exchange of used random number generators. For example
 * test cases utilize a FakeRandomGenerator that returns the
 * same number -- this allows to easily compare test results.
 * 
 * @author Andreas Happe <andreashappe@snikt.net>
 */
public interface RandomSource {
	public int generateByte();
}
