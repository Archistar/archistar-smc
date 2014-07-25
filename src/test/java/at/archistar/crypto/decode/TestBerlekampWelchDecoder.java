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
		
		x = new int[n];
		y = new int[n];
		for (int i = 0; i < x.length; i++) {
			x[i] = rng.generateByte();
			y[i] = poly.evaluateAt(x[i]);
		}
		
		for (int i = 0; i < f; i++) {
			int index = rng.generateByte() % y.length;
			
			int rand;
			do
				rand = rng.generateByte();
			while (rand == y[index]); // ensure making f changes
			
			y[index] = rand;
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
