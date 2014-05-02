package at.archistar.crypto.math;

import de.flexiprovider.common.math.codingtheory.GF2mField;

/**
 * GF(2^8) arithmetic
 *
 * For more information about operations in finite fields see
 *
 *  * https://en.wikipedia.org/wiki/Finite_fields *
 * https://en.wikipedia.org/wiki/Finite_field_arithmetic
 *
 * @author Fehrenbach Franca-Sofia
 * @author Andreas Happe <andreashappe@snikt.net>
 *
 */
public class GF256 {

    public static final GF2mField gf256 = new GF2mField(8, 0x11d);

    public static int add(int a, int b) {

        a = (a < 0) ? a + 256 : a;
        b = (b < 0) ? b + 256 : b;

        assert (a >= 0 && a <= 255);
        assert (b >= 0 && b <= 255);

        int result = gf256.add(a, b) & 0xFF;
        assert (result >= 0 && result <= 255);
        return result;
    }

    /**
     * NOTE: in a GF(2^8) addition and subtraction is essential the same
     * operation
     */
    public static int sub(int a, int b) {

        a = (a < 0) ? a + 256 : a;
        b = (b < 0) ? b + 256 : b;

        assert (a >= 0 && a <= 255);
        assert (b >= 0 && b <= 255);

        int result = gf256.add(a, b) & 0xFF;
        assert (result >= 0 && result <= 255);
        return result;
    }

    public static int mult(int a, int b) {

        a = (a < 0) ? a + 256 : a;
        b = (b < 0) ? b + 256 : b;

        assert (a >= 0 && a <= 255);
        assert (b >= 0 && b <= 255);

        int result = gf256.mult(a, b) & 0xFF;
        assert (result >= 0 && result <= 255);
        return result;
    }

    public static int div(int a, int b) {

        assert (a >= 0 && a <= 255);
        assert (b >= 0 && b <= 255);

        int result = gf256.mult(a, gf256.inverse(b)) & 0xFF;
        assert (result >= 0 && result <= 255);
        return result;
    }

    /**
     * Calculates the a power p. Sets the result as the new value of this
     * object. Remember that x^0 = 1.
     */
    public static int pow(int a, int p) {

        a = (a < 0) ? a + 256 : a;
        p = (p < 0) ? p + 256 : p;

        assert (a >= 0 && a <= 255);
        assert (p >= 0 && p <= 255);

        int result = gf256.exp(a, p);

        assert (result >= 0 && result <= 255);
        return result;
    }
}
