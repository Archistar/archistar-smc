package at.archistar.crypto.math;

import org.bouncycastle.pqc.math.linearalgebra.GF2mField;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialGF2mSmallM;
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
        
        private final GF256 gf = new GF256();
	
	/* test values */
	private final int a = 117;
	private final int b = 98;
	
	/* basic operation tests */
	
	@Test
	public void testAdd() {
		assertEquals(gf256.add(a, b), gf.add(a, b));
	}
	
	@Test
	public void testSubtract() {
		assertEquals(gf256.add(a, b), gf.sub(a, b));
	}
	
	@Test
	public void testMult() {
		assertEquals(gf256.mult(a, b), gf.mult(a, b));
	}
	
	@Test
	public void testDiv() {
		assertEquals(gf256.mult(a, gf256.inverse(b)), gf.div(a, b));
	}
	
	@Test
	public void testPow() {
		assertEquals(gf256.exp(a, b), gf.pow(a, b));
	}
	
	@Test
	public void testInverse() {
		assertEquals(gf256.inverse(a), gf.inverse(a));
	}
	
	/* special cases / Exception tests */
	
	@Test(expected = ArithmeticException.class)
	public void divBy0() {
            gf.div(a, 0);
	}
        
        @Test
	public void testEvaluate() {
            
            final int[] coeffs = {1, 2, 3, 4, 5, 6};
            final int x = 117;
	
            /* the reference implementation of flexiprovider */
            final PolynomialGF2mSmallM refPoly = new PolynomialGF2mSmallM(new GF2mField(8, 0x11d), coeffs);

            assertEquals(refPoly.evaluateAt(x), gf.evaluateAt(coeffs, x));
	}
}
