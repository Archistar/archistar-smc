package at.archistar.crypto.math;

import java.util.Arrays;

/**
 * TODO: refactor or rewrite. But make it faster and more beautiful
 */
public class GenericPolyHelper {

    private final GF gf;

    /**
     * create a new helper for operations upon polynomials within the field gf
     * 
     * @param gf the field within which operations will be performed
     */
    public GenericPolyHelper(GF gf) {
        this.gf = gf;
    }

    /**
     * divide polynom a with polynom f
     *
     * @param a perform a/f
     * @param f perform a/f
     * @return the result
     */
    public int[][] polyDiv(int a[], int f[]) {
        int df = computeDegree(f);
        int da = computeDegree(a) + 1;
        if (df == -1) {
            throw new ArithmeticException("Division by zero.");
        }
        int[][] result = new int[2][];
        result[0] = new int[1];
        result[1] = new int[da];
        int hc = headCoefficient(f);
        hc = gf.inverse(hc);
        result[0][0] = 0;
        System.arraycopy(a, 0, result[1], 0, result[1].length);
        while (df <= computeDegree(result[1])) {
            int[] q;
            int[] coeff = new int[1];
            coeff[0] = gf.mult(headCoefficient(result[1]), hc);
            q = multWithElement(f, coeff[0]);
            int n = computeDegree(result[1]) - df;
            q = multWithMonomial(q, n);
            coeff = multWithMonomial(coeff, n);
            result[0] = sub(coeff, result[0]);
            result[1] = sub(q, result[1]);
        }
        return result;
    }

    private static int[] multWithMonomial(int[] a, int k) {
        int d = computeDegree(a);
        if (d == -1) {
            return new int[1];
        }
        int[] result = new int[d + k + 1];
        System.arraycopy(a, 0, result, k, d + 1);
        return result;
    }

    private int[] multWithElement(int[] a, int element) {
        int degree = computeDegree(a);
        if (degree == -1 || element == 0) {
            return new int[1];
        }

        if (element == 1) {
            return Arrays.copyOf(a, a.length);
        }

        int[] result = new int[degree + 1];
        for (int i = degree; i >= 0; i--) {
            result[i] = gf.mult(a[i], element);
        }

        return result;
    }

    private static int headCoefficient(int[] a) {
        int degree = computeDegree(a);
        return (degree == -1) ? 0 : a[degree];
    }

    @SuppressWarnings("empty-statement")
    private static int computeDegree(int[] a) {
        int degree;
        for (degree = a.length - 1; degree >= 0 && a[degree] == 0; degree--) {
            //empty
        }
        return degree;
    }

    private int[] sub(int[] a, int[] b) {
        // TODO: optimize
        //assert(a.length == b.length);
        int[] result, addend;
        if (a.length < b.length) {
            result = new int[b.length];
            System.arraycopy(b, 0, result, 0, b.length);
            addend = a;
        } else {
            result = new int[a.length];
            System.arraycopy(a, 0, result, 0, a.length);
            addend = b;
        }

        for (int i = addend.length - 1; i >= 0; i--) {
            result[i] = gf.sub(result[i], addend[i]);
        }

        return result;
    }

    /**
     * add two polynomials
     * 
     * @param a
     * @param b
     * @return a+b
     */
    public int[] add(int[] a, int[] b) {

        // TODO: optimize
        //assert(a.length == b.length);
        int[] result, addend;
        if (a.length < b.length) {
            result = new int[b.length];
            System.arraycopy(b, 0, result, 0, b.length);
            addend = a;
        } else {
            result = new int[a.length];
            System.arraycopy(a, 0, result, 0, a.length);
            addend = b;
        }

        for (int i = addend.length - 1; i >= 0; i--) {
            result[i] = gf.add(result[i], addend[i]);
        }

        return result;
    }

    /** multiply 2 polynomials
     * 
     * @param a
     * @param b
     * @return a*b
     */
    public int[] multiply(int[] a, int[] b) {
        int[] mult1, mult2;
        if (computeDegree(a) < computeDegree(b)) {
            mult1 = b;
            mult2 = a;
        } else {
            mult1 = a;
            mult2 = b;
        }

        mult1 = normalForm(mult1);
        mult2 = normalForm(mult2);

        if (mult2.length == 1) {
            return multWithElement(mult1, mult2[0]);
        }

        int d1 = mult1.length;
        int d2 = mult2.length;
        int[] result = new int[d1 + d2 - 1];

        if (d2 != d1) {
            int[] res1 = new int[d2];
            int[] res2 = new int[d1 - d2];
            System.arraycopy(mult1, 0, res1, 0, res1.length);
            System.arraycopy(mult1, d2, res2, 0, res2.length);
            res1 = multiply(res1, mult2);
            res2 = multiply(res2, mult2);
            res2 = multWithMonomial(res2, d2);
            result = add(result, res1);
            result = add(result, res2);
        } else {
            d2 = (d1 + 1) >>> 1;
            int d = d1 - d2;
            int[] firstPartMult1 = new int[d2];
            int[] firstPartMult2 = new int[d2];
            int[] secondPartMult1 = new int[d];
            int[] secondPartMult2 = new int[d];
            System.arraycopy(mult1, 0, firstPartMult1, 0, firstPartMult1.length);
            System.arraycopy(mult1, d2, secondPartMult1, 0, secondPartMult1.length);
            System.arraycopy(mult2, 0, firstPartMult2, 0, firstPartMult2.length);
            System.arraycopy(mult2, d2, secondPartMult2, 0, secondPartMult2.length);
            int[] helpPoly1 = add(firstPartMult1, secondPartMult1);
            int[] helpPoly2 = add(firstPartMult2, secondPartMult2);
            int[] res1 = multiply(firstPartMult1, firstPartMult2);
            int[] res2 = multiply(helpPoly1, helpPoly2);
            int[] res3 = multiply(secondPartMult1, secondPartMult2);
            res2 = add(res2, res1);
            res2 = add(res2, res3);
            res3 = multWithMonomial(res3, d2);
            result = add(res2, res3);
            result = multWithMonomial(result, d2);
            result = add(result, res1);
        }

        return result;
    }

    private static int[] normalForm(int[] a) {
        int d = computeDegree(a);

        // if a is the zero polynomial
        if (d == -1) {
            // return new zero polynomial
            return new int[1];
        }

        // if a already is in normal form
        if (a.length == d + 1) {
            // return a clone of a
            return Arrays.copyOf(a, a.length);
        }

        // else, reduce a
        int[] result = new int[d + 1];
        System.arraycopy(a, 0, result, 0, d + 1);
        return result;
    }
}
