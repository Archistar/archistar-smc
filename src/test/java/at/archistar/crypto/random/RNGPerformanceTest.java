package at.archistar.crypto.random;

import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import at.archistar.crypto.random.CTRPRNG;
import at.archistar.crypto.random.RandomSource;
import at.archistar.crypto.random.SHA1PRNG;
import at.archistar.crypto.random.StreamPRNG;

/**
 * This class tests and compares the performance of the different secure RandomNumberGenerators.
 * @author Elias Frantar
 * @version 2014-7-18
 */
@RunWith(value = Parameterized.class)
public class RNGPerformanceTest {
	private RandomSource rng;
	
	public RNGPerformanceTest(RandomSource rng) {
		this.rng = rng;
	}
	
	@Parameters
    public static Collection<Object[]> data() {
    	Object[][] data = null;
    	try {
	        data = new Object[][]{
	        		{new StreamPRNG(StreamPRNG.SALSA20)},
	        		{new StreamPRNG(StreamPRNG.HC128)},
	                {new CTRPRNG()},
	        		{new SHA1PRNG()}
	        };
    	} catch(Exception e) {} // should never happen

        return Arrays.asList(data);
    }
	
	@Test
	public void testPerformance() {
		long start = System.currentTimeMillis();
		for(int i = 0;i < 1024 * 1024 * 500;i++) {
			rng.generateByte();
		}
		long end = System.currentTimeMillis();
		
		System.out.println(rng.toString() + ": 500MB in " + (end - start) + "ms");
	}
}
