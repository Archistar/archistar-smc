package at.archistar.crypto.math;

import org.bouncycastle.pqc.math.linearalgebra.GF2mField;
import static org.junit.Assert.*;

import org.junit.Test;

/**
 * <p>A simple unit-test for {@link GF256}.</p>
 * 
 * <p>All arithmetic operations are tested by comparing the result with the reference-result of the flexiprovider-API
 * (which is expected to work properly).</p>
 */
public class TestGF256 {
	/* reference GF */
	private final GF2mField gf256 = new GF2mField(8, 0x11d); // Galois-Field (x^8 + x^4 + x^3 + x + 1 = 0)
	
	/* test values */
	private final int a = 117;
	private final int b = 98;
	
	/* basic operation tests */
	
	@Test
	public void testAdd() {
		assertEquals(gf256.add(a, b), GF256.add(a, b));
	}
	
	@Test
	public void testSubtract() {
		assertEquals(gf256.add(a, b), GF256.sub(a, b));
	}
	
	@Test
	public void testMult() {
		assertEquals(gf256.mult(a, b), GF256.mult(a, b));
	}
	
	@Test
	public void testDiv() {
		assertEquals(gf256.mult(a, gf256.inverse(b)), GF256.div(a, b));
	}
	
	@Test
	public void testPow() {
		assertEquals(gf256.exp(a, b), GF256.pow(a, b));
	}
	
	@Test
	public void testInverse() {
		assertEquals(gf256.inverse(a), GF256.inverse(a));
	}
	
	/* special cases / Exception tests */
	
	@Test(expected = ArithmeticException.class)
	public void divBy0() {
		GF256.div(a, 0);
	}
}
