package at.archistar.crypto.decode;

import static org.junit.Assert.*;

import org.junit.Test;

import de.flexiprovider.common.math.codingtheory.GF2mField;
import de.flexiprovider.common.math.codingtheory.PolynomialGF2mSmallM;
import at.archistar.crypto.random.RandomSource;
import at.archistar.crypto.random.SHA1PRNG;
import org.junit.Assert;

/**
 * Basic tests for {@link BerlekampWelchDecoder}
 *
 * @author Andreas Happe
 * @author Elias Frantar
 * @version 2014-7-25
 */
public class TestBerlekampWelchDecoder {

    /**
     * Generates a random array of the given size in O(r) time. This array will
     * have distinct integers of the given range.
     *
     * It is important that n <= r <= 256. 
   * @
     *
     * param n the number of bytes
     * @param r the range of the numbers will be in the range [0, r - 1]
     */
    void generateRandomIntegerArray(int ret[], int n, int r) {
        assert (n <= r && r <= 256);

        RandomSource rng = new SHA1PRNG();
        int num[] = new int[r];

        for (int i = 0; i < r; i++) {
            num[i] = i;
        }

        // Use Fisher-Yates algorithm to shuffle this array. 
        for (int i = num.length - 1; i >= 1; i--) {
            int j = rng.generateByte() % i;
            int tmp = num[i];
            num[i] = num[j];
            num[j] = tmp;
        }
        System.arraycopy(num, 0, ret, 0, n);
    }

    /**
     * Generates a new random test-case with given parameters.
     *
     * @param coeffs the number of coefficients of the polynomial
     * @param n the number of points of the polynomial
     * @param f the number of faulty points
     */
    private void genRandomTest(int x[], int y[], int expected[], int coeffs, int n, int f) {
        RandomSource rng = new SHA1PRNG();

        expected = new int[coeffs];
        for (int i = 0; i < expected.length; i++) {
            expected[i] = rng.generateByte();
        }

        PolynomialGF2mSmallM poly = new PolynomialGF2mSmallM(new GF2mField(8, 0x11d), expected);

        generateRandomIntegerArray(x, n, 256);
        for (int i = 0; i < x.length; i++) {
            y[i] = poly.evaluateAt(x[i]);
        }

        int[] idx = new int[n];
        int[] delta = new int[255];
        
        generateRandomIntegerArray(idx, f, n);
        generateRandomIntegerArray(delta, f, 255);

        // Adding a number in range [1, 255] to a number will change it for sure. 
        for (int i = 0; i < f; i++) {
            y[idx[i]] = (y[idx[i]] + delta[i] + 1) % 256;
        }
    }

    @Test
    public void testErrorDecodeAll4Correct() {
        // f = 1;
        int[] x = {17, 114, 98, 213}; // 17, 114, 98, 213
        int[] y = {153, 174, 168, 62}; // 153, 174, 168, 62
        int[] expected = {117, 234};

        Decoder polySolver = new BerlekampWelchDecoderFactory(expected.length - 1).createDecoder(x);
        assertArrayEquals(expected, polySolver.decode(y));
    }

    @Test
    public void testErrorDecode41YWrong() {
        // f = 1;
        int[] x = {17, 114, 98, 213}; // 17, 114, 98, 213
        int[] y = {153, 174, 244, 62}; // 153, 174, 168, 62
        int[] expected = {117, 234};

        Decoder polySolver = new BerlekampWelchDecoderFactory(expected.length - 1).createDecoder(x);
        assertArrayEquals(expected, polySolver.decode(y));
    }

    @Test
    public void testErrorDecode41XWrong() {
        // f = 1;
        int[] x = {17, 127, 98, 213}; // 17, 114, 98, 213
        int[] y = {153, 174, 168, 62}; // 153, 174, 168, 62
        int[] expected = {117, 234};

        Decoder polySolver = new BerlekampWelchDecoderFactory(expected.length - 1).createDecoder(x);
        assertArrayEquals(expected, polySolver.decode(y));
    }

    @Test
    public void testErrorDecodeRandom82() {
        
        int n = 8;
        int coeffs = 2;
        
        int[] x = new int[n];
        int[] y = new int[n];
        int[] expected = new int[coeffs];

        genRandomTest(x, y, expected, coeffs, n, 2); // f = 3;

        Decoder polySolver = new BerlekampWelchDecoderFactory(expected.length - 1).createDecoder(x);
        assertArrayEquals(expected, polySolver.decode(y));
    }

    @Test
    public void testErrorDecode51Wrong() {
        // f = 1;
        int[] x = {137, 23, 223, 99, 158}; // 137, 23, 223, 99, 158
        int[] y = {37, 225, 176, 89, 210}; // 37, 224, 176, 89, 210
        int[] expected = {23, 235, 78};

        Decoder polySolver = new BerlekampWelchDecoderFactory(expected.length - 1).createDecoder(x);
        assertArrayEquals(expected, polySolver.decode(y));
    }

    @Test
    public void testErrorDecode85WrongFail() {
        
        int n = 8;
        int coeffs = 2;
        
        int[] x = new int[n];
        int[] y = new int[n];
        int[] expected = new int[coeffs];
        
        genRandomTest(x, y, expected, coeffs, n, 5);

        Decoder polySolver = new BerlekampWelchDecoderFactory(expected.length - 1).createDecoder(x);
        Assert.assertEquals(null, polySolver.decode(y));
    }
}
