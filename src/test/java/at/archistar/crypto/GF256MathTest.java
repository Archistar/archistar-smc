package at.archistar.crypto;

import static org.junit.Assert.*;

import org.junit.Test;

import at.archistar.crypto.math.GF256Math;
import de.flexiprovider.common.math.codingtheory.GF2mField;

/**
 * <p>A simple unit-test for {@link GF256Math}.</p>
 * 
 * <p>All arithmetic operations are tested by comparing the result with the reference-result of the flexiprovider-API
 * (which is expected to work properly).</p>
 * 
 * @author Elias Frantar
 * @version 2014-7-17
 */
public class GF256MathTest {
	/* reference GF */
	private final GF2mField gf256 = new GF2mField(8, 0x11d); // Galois-Field (x^8 + x^4 + x^3 + x + 1 = 0)
	
	/* test values */
	private final int a = 117;
	private final int b = 98;
	
	/* basic operation tests */
	
	@Test
	public void testAdd() {
		assertEquals(gf256.add(a, b), GF256Math.add(a, b));
	}
	
	@Test
	public void testSubtract() {
		assertEquals(gf256.add(a, b), GF256Math.sub(a, b));
	}
	
	@Test
	public void testMult() {
		assertEquals(gf256.mult(a, b), GF256Math.mult(a, b));
	}
	
	@Test
	public void testDiv() {
		assertEquals(gf256.mult(a, gf256.inverse(b)), GF256Math.div(a, b));
	}
	
	@Test
	public void testPow() {
		assertEquals(gf256.exp(a, b), GF256Math.pow(a, b));
	}
	
	@Test
	public void testInverse() {
		assertEquals(gf256.inverse(a), GF256Math.inverse(a));
	}
	
	/* special cases / Exception tests */
	
	@Test(expected = ArithmeticException.class)
	public void divBy0() {
		GF256Math.div(a, 0);
	}
}