package at.archistar.crypto;

import java.util.Arrays;
import java.util.Collection;
import java.util.Random;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import at.archistar.crypto.KrawczykCSS;
import at.archistar.crypto.RabinBenOrRSS;
import at.archistar.crypto.RabinIDS;
import at.archistar.crypto.SecretSharing;
import at.archistar.crypto.ShamirPSS;
import at.archistar.crypto.data.Share;
import at.archistar.crypto.random.FakeRandomSource;
import at.archistar.crypto.random.RandomSource;
import static org.fest.assertions.api.Assertions.*;

/**
	- * @author Andreas Happe <andreashappe@snikt.net>
 */
@RunWith(value = Parameterized.class)
public class PerformanceTest {

	private final byte[] input;
	
	private final SecretSharing algorithm;

	@Parameters
	public static Collection<Object[]> data() {
		Random rnd = new Random();

		byte[] secret1MB = new byte[4*1024*1024];
		rnd.nextBytes(secret1MB);
		
		final int n = 8;
		final int k = 5;
		
		RandomSource rng = new FakeRandomSource();

		Object[][] data = new Object[][] {
				{ secret1MB, new ShamirPSS(n, k, rng) },
				{ secret1MB, new RabinIDS(n, k) },
				{ secret1MB, new KrawczykCSS(n, k, rng) },
				{ secret1MB, new RabinBenOrRSS(n, k, rng, new KrawczykCSS(n, k, rng)) }
		};

		return Arrays.asList(data);
	}

	public PerformanceTest(byte[] input, SecretSharing algorithm) {
		this.input = input;
		this.algorithm = algorithm;
	}

	@Test
	public void testPerformance() throws Exception {

		/* test construction */
		long beforeShare = System.currentTimeMillis();
		Share[] shares = algorithm.share(this.input);
		
		long betweenOperations = System.currentTimeMillis();
		
		byte[] reconstructed = algorithm.reconstruct(shares);
		
		long afterAll = System.currentTimeMillis();
		
		double dataLength = ((double)this.input.length)/(1024);
		double timeShare = dataLength/((betweenOperations-beforeShare)/1000.0);
		double timeReconstruct = dataLength/((afterAll - betweenOperations)/1000.0);
				
		System.err.format("Performance of %s: share: %.2fkB/sec, combine: %.2fkB/sec\n", this.algorithm, timeShare, timeReconstruct);
	
		/* test that the reconstructed stuff is the same as the original one */
		assertThat(reconstructed).isEqualTo(input);
	}
}
