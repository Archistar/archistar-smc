package at.archistar.crypto.decode;

import at.archistar.crypto.math.GFFactory;
import at.archistar.crypto.math.gf256.GF256Factory;
import org.junit.Test;

import at.archistar.crypto.random.RandomSource;
import at.archistar.crypto.random.JavaSecureRandom;
import org.bouncycastle.pqc.math.linearalgebra.GF2mField;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialGF2mSmallM;
import org.bouncycastle.util.Arrays;

import static org.fest.assertions.api.Assertions.assertThat;

/**
 * Basic BerlekampWelch-Decoder Test
 */
public class TestBerlekampWelchDecoder {

    private static final GFFactory gffactory = new GF256Factory();

    /**
     * Generates a random array of the given size in O(r) time. This array will
     * have distinct integers of the given range.
     *
     * It is important that n <= r <= 256.
     *
     * @param n the number of bytes
     * @param r the range of the numbers will be in the range [0, r - 1]
     */
    void generateRandomIntegerArray(int ret[], int n, int r) {
        assert (n <= r && r <= 256);

        RandomSource rng = new JavaSecureRandom();
        int num[] = new int[r];

        for (int i = 0; i < r; i++) {
            num[i] = i;
        }

        int tmpBytes[] = new int[1];

        // Use Fisher-Yates algorithm to shuffle this array.
        for (int i = num.length - 1; i >= 1; i--) {
            rng.fillBytesAsInts(tmpBytes);
            int j = tmpBytes[0] % i;
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
        RandomSource rng = new JavaSecureRandom();
        rng.fillBytesAsInts(expected);

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
    public void testErrorDecodeAll4Correct() throws UnsolvableException {
        // f = 1;
        int[] x = {17, 114, 98, 213}; // 17, 114, 98, 213
        int[] y = {153, 174, 168, 62}; // 153, 174, 168, 62
        int[] expected = {117, 234};

        Decoder polySolver = new BerlekampWelchDecoder(x, 2, gffactory);
        assertThat(polySolver.decode(y, 0)).isEqualTo(expected);
    }

    @Test
    public void testErrorDecode41YWrong() throws UnsolvableException {
        // f = 1;
        int[] x = {17, 114, 98, 213}; // 17, 114, 98, 213
        int[] y = {153, 174, 244, 62}; // 153, 174, 168, 62
        int[] expected = {117, 234};

        Decoder polySolver = new BerlekampWelchDecoder(x, 2, gffactory);
        assertThat(polySolver.decode(y, 1)).isEqualTo(expected);
    }

    @Test
    public void testErrorDecode41XWrong() throws UnsolvableException {
        // f = 1;
        int[] x = {17, 127, 98, 213}; // 17, 114, 98, 213
        int[] y = {153, 174, 168, 62}; // 153, 174, 168, 62
        int[] expected = {117, 234};

        Decoder polySolver = new BerlekampWelchDecoder(x, 2, gffactory);
        assertThat(polySolver.decode(y, 1)).isEqualTo(expected);
    }

    @Test
    public void testErrorDecodeRandom82() throws UnsolvableException {

        int n = 8;
        int coeffs = 2;
        int f = 2;

        int[] x = new int[n];
        int[] y = new int[n];
        int[] expected = new int[coeffs];

        genRandomTest(x, y, expected, coeffs, n, f);

        Decoder polySolver = new BerlekampWelchDecoder(x, coeffs, gffactory);
        assertThat(polySolver.decode(y, f)).isEqualTo(expected);
    }

    @Test
    public void testErrorDecode51Wrong() throws UnsolvableException {
        // f = 1;
        int[] x = {137, 23, 223, 99, 158}; // 137, 23, 223, 99, 158
        int[] y = {37, 225, 176, 89, 210}; // 37, 224, 176, 89, 210
        int[] expected = {23, 235, 78};

        Decoder polySolver = new BerlekampWelchDecoder(x, 3, gffactory);
        assertThat(polySolver.decode(y, 1)).isEqualTo(expected);
    }

    @Test(expected = UnsolvableException.class)
    public void testErrorDecode85WrongFail() throws UnsolvableException {

        final int n = 8;
        final int f = 5;
        final int coeffs = 2;

        int[] x = new int[n];
        int[] y = new int[n];
        int[] expected = new int[coeffs];

        genRandomTest(x, y, expected, coeffs, n, f);

        Decoder polySolver = new BerlekampWelchDecoder(x, coeffs, gffactory);
        polySolver.decode(y, f);
    }
}
