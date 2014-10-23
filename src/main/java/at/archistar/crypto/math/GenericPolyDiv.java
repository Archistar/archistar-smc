package at.archistar.crypto.math;

import java.util.Arrays;

/**
 *
 * @author andy
 */
public class GenericPolyDiv {
    
    private final GF gf;
    
    public GenericPolyDiv(GF gf) {
        this.gf = gf;
    }
        
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
            result[0] = add(coeff, result[0]);
            result[1] = add(q, result[1]);
        }
        return result;
    }
    
    private static int[] multWithMonomial(int[] a, int k)
    {
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
    
     private int[] add(int[] a, int[] b) {
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
    
     private static int headCoefficient(int[] a) {
        int degree = computeDegree(a);
        return (degree == -1) ? 0 : a[degree];
    }
    
    @SuppressWarnings("empty-statement")
     private static int computeDegree(int[] a) {
        int degree;
        for (degree = a.length - 1; degree >= 0 && a[degree] == 0; degree--);
        return degree;
    }
}
