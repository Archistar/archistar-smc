package at.archistar.crypto.math;

import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import at.archistar.crypto.math.GF256Polynomial;
import de.flexiprovider.common.math.codingtheory.GF2mField;
import de.flexiprovider.common.math.codingtheory.PolynomialGF2mSmallM;

/**
 * <p>A simple unit-test for {@link GF256Polynomial}.</p>
 * 
 * <p>Most of the functions are tested by comparing the result with the reference-result of the flexiprovider-API
 * (which is expected to work properly).</p>
 * 
 * @author Elias Frantar
 * @version 2014-7-21
 */
public class TestGF256Polynomial {
	/* the constants used for testing */
	private final int[] coeffs = {1, 2, 3, 4, 5, 6};
	private final int x = 117;
	
	/* the reference implementation of flexiprovider */
	private final PolynomialGF2mSmallM refPoly = new PolynomialGF2mSmallM(new GF2mField(8, 0x11d), coeffs);
	
	private GF256Polynomial poly;
	
	/* setup and tearDown */
	@Before
	public void setup() {
		poly = new GF256Polynomial(coeffs);
	}
	@After
	public void tearDown() {
		poly = null;
	}
	
	/* basic functionality tests */
	
	@Test
	public void testEvaluate() {
		assertEquals(refPoly.evaluateAt(x), poly.evaluateAt(x));
	}
}
