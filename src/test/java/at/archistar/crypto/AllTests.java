package at.archistar.crypto;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

/**
 * Executes all tests. (excluding {@link PerformanceTest} and {@link RNGPerformanceTest})
 * @author Elias Frantar
 * @version 2014-7-17
 */
@RunWith(Suite.class)
@SuiteClasses(
	  { RabinBenOrTest.class, GF256MathTest.class,
		GF256PolynomialTest.class, KrawczykCSSTest.class, ReedSolomonTest.class,
		ShamirPSSTest.class, USRSSTest.class, ShareSerializerTest.class })
public class AllTests {}