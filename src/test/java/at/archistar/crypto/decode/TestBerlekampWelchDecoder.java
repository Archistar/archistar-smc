package at.archistar.crypto.decode;

import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Test;

import de.flexiprovider.common.math.codingtheory.GF2mField;
import de.flexiprovider.common.math.codingtheory.PolynomialGF2mSmallM;
import at.archistar.crypto.decode.BerlekampWelchDecoder;
import at.archistar.crypto.decode.PolySolver;
import at.archistar.crypto.random.RandomSource;
import at.archistar.crypto.random.SHA1PRNG;

/**
 * Basic tests for {@link BerlekampWelchDecoder}
 * @author Elias Frantar
 * @version 2014-7-25
 */
public class TestBerlekampWelchDecoder {
  private PolySolver polySolver;
	
  private int[] x;
  private int[] y;
  private int[] expected;

  /**
   * Generates a random array of the given size in O(r) time. 
   * This array will have distinct integers of the given range. 
   * 
   * It is important that n <= r <= 256. 
   * @param n the number of bytes
   * @param r the range of the numbers will be in the range [0, r - 1]
   */
  int [] generateRandomIntegerArray(int n, int r){
    assert(n <= r && r <= 256);

    RandomSource rng = new SHA1PRNG();
    int ret[] = new int[n];
    int num[] = new int[r];

    for(int i = 0; i < r; i++)
      num[i] = i;

    // Use Fisher-Yates algorithm to shuffle this array. 
    for(int i = num.length - 1; i >= 1; i--){
      int j = rng.generateByte() % i;
      int tmp = num[i];
      num[i] = num[j];
      num[j] = tmp;
    }
    for(int i = 0; i < n; i++){
      ret[i] = num[i];
    }
    return ret;
  }
	/**
	 * Generates a new random test-case with given parameters.
	 * 
	 * @param coeffs the number of coefficients of the polynomial
	 * @param n the number of points of the polynomial
	 * @param f the number of faulty points
	 */
	private void genRandomTest(int coeffs, int n, int f) {
		RandomSource rng = new SHA1PRNG();
		
		expected = new int[coeffs];
		for (int i = 0; i < expected.length; i++)
			expected[i] = rng.generateByte();
		
		PolynomialGF2mSmallM poly = new PolynomialGF2mSmallM(new GF2mField(8, 0x11d), expected);
		
		x = generateRandomIntegerArray(n, 256);
		y = new int[n];
		for (int i = 0; i < x.length; i++) {
		  y[i] = poly.evaluateAt(x[i]);
		}
		
		int[] idx = generateRandomIntegerArray(f, n);
		int[] delta = generateRandomIntegerArray(f, 255);

		// Adding a number in range [1, 255] to a number will change it for sure. 
		for(int i = 0; i < f; i++){
		  y[idx[i]] = (y[idx[i]] + delta[i] + 1) % 256;
		}
	}
	
  @After
	public void tearDown() {
		x = null;
		y = null;
		expected = null;
	}
	
	@Test
	public void testErrorDecodeAll4Correct() {
		// f = 1;
		int[] x = {17, 114, 98, 213}; // 17, 114, 98, 213
		int[] y = {153, 174, 168, 62}; // 153, 174, 168, 62
		int[] expected = {117, 234};
		
		polySolver = new BerlekampWelchDecoder(expected.length - 1);
		polySolver.prepare(x);
		
		assertArrayEquals(expected, polySolver.solve(y));
	}
	
	@Test
	public void testErrorDecode41YWrong() {
		// f = 1;
		int[] x = {17, 114, 98, 213}; // 17, 114, 98, 213
		int[] y = {153, 174, 244, 62}; // 153, 174, 168, 62
		int[] expected = {117, 234};
		
		polySolver = new BerlekampWelchDecoder(expected.length - 1);
		polySolver.prepare(x);
		
		assertArrayEquals(expected, polySolver.solve(y));
	}
	@Test
	public void testErrorDecode41XWrong() {
		// f = 1;
		int[] x = {17, 127, 98, 213}; // 17, 114, 98, 213
		int[] y = {153, 174, 168, 62}; // 153, 174, 168, 62
		int[] expected = {117, 234};
		
		polySolver = new BerlekampWelchDecoder(expected.length - 1);
		polySolver.prepare(x);
		
		assertArrayEquals(expected, polySolver.solve(y));
	}
	@Test
	public void testErrorDecodeRandom82() {
		genRandomTest(2, 8, 2); // f = 3;
		
		polySolver = new BerlekampWelchDecoder(expected.length - 1);
		polySolver.prepare(x);
		
		assertArrayEquals(expected, polySolver.solve(y));
	}
	
	@Test
	public void testErrorDecode51Wrong() {
		// f = 1;
		int[] x = {137, 23, 223, 99, 158}; // 137, 23, 223, 99, 158
		int[] y = {37, 225, 176, 89, 210}; // 37, 224, 176, 89, 210
		int[] expected = {23, 235, 78};
		
		polySolver = new BerlekampWelchDecoder(expected.length - 1);
		polySolver.prepare(x);
		
		assertArrayEquals(expected, polySolver.solve(y));
	}
	
	@Test
	public void testErrorDecode85WrongFail() { // TODO: This test-case fails sometimes for unknown reasons. Fix this!
		// f = 3;
		genRandomTest(2, 8, 5);
		
		polySolver = new BerlekampWelchDecoder(expected.length - 1);
		polySolver.prepare(x);
		
		assertEquals(null, polySolver.solve(y));
	}
}
