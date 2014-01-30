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

	private final byte[][][] input;
	
	private final SecretSharing algorithm;

  private static final int size = 20*1024*1024;

  private static byte[][] createArray(int elementSize) {
    byte[][] result = new byte[size/elementSize][elementSize];
		Random rnd = new Random();

    for(int i=0; i < size/elementSize; i++) {
      for(int j=0; j < elementSize; j++) {
        result[i][j] = 42;
      }
    }

    return result;
  }

	@Parameters
	public static Collection<Object[]> data() {

		byte[][][] secrets = new byte[7][][];
    secrets[0] = createArray(4*1024);
    secrets[1] = createArray(32*1024);
    secrets[2] = createArray(64*1024);
    secrets[3] = createArray(256*1024);
    secrets[4] = createArray(512*1024);
    secrets[5] = createArray(1024*1024);
    secrets[6] = createArray(4096*1024);

		final int n = 4;
		final int k = 3;
		
		RandomSource rng = new FakeRandomSource();
		Object[][] data = new Object[][] {
				{ secrets, new ShamirPSS(n, k, rng) },
				{ secrets, new RabinIDS(n, k) },
				{ secrets, new KrawczykCSS(n, k, rng) },
				{ secrets, new RabinBenOrRSS(n, k, rng, new KrawczykCSS(n, k, rng)) }
		};

		return Arrays.asList(data);
	}

	public PerformanceTest(byte[][][] input, SecretSharing algorithm) {
		this.input = input;
		this.algorithm = algorithm;
	}

	@Test
	public void testPerformance() throws Exception {

    for (int i =0; i < 7 ; i++) {
      double sumShare = 0;
      double sumCombine = 0;

      for(byte[] data : this.input[i]) {
		    /* test construction */
    		long beforeShare = System.currentTimeMillis();
  	  	Share[] shares = algorithm.share(data);
    		long betweenOperations = System.currentTimeMillis();
  	  	byte[] reconstructed = algorithm.reconstruct(shares);
    		long afterAll = System.currentTimeMillis();
		
    		sumShare += (betweenOperations-beforeShare);
    		sumCombine += (afterAll - betweenOperations);
	
    		/* test that the reconstructed stuff is the same as the original one */
    		assertThat(reconstructed).isEqualTo(data);
      }
				
  		System.err.format("Performance(%d) of %s: share: %.3fmsec, combine: %.2fmsec\n", i, this.algorithm, sumShare, sumCombine);
    }
	}
}
