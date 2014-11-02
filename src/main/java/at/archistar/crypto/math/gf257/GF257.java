package at.archistar.crypto.math.gf257;

import at.archistar.crypto.math.GF;

/**
 *
 * @author andy
 */
public class GF257 implements GF {
    
    private static final int invTable[];
    
    private static final int exp[][];
    
    private static final int precalcExp = 6;
    
    static {
        invTable = new int[257];
        for (int i = 0; i < 257; i++) {
            invTable[i] = calcInverse(i);
        }
        
        exp = new int[257][precalcExp];
        
        for (int i = 0; i < 257; i++) {
            for (int j = 0; j < precalcExp; j++) {
                exp[i][j] = ((int)Math.pow(i, j)) % 257;
            }
        }
    }

    @Override
    public int add(int a, int b) {
        return (a+b)%257;
    }

    @Override
    public int sub(int a, int b) {
        int tmp = a -b;
        return ((tmp < 0) ? (tmp + this.getFieldSize()) : tmp)%257;
    }

    @Override
    public int mult(int a, int b) {
        return (a*b)%257;
    }

    @Override
    public int pow(int a, int b) {
        if (b < precalcExp) {
            return exp[a][b];
        } else {
            return ((int)Math.pow(a, b)) % 257;
        }
    }

    @Override
    public int div(int a, int b) {
        return (a/b)%257;
    }

    @Override
    public int evaluateAt(int[] coeffs, int x) {
        int degree = coeffs.length -1;
        
        int result = coeffs[degree];
        for (int i = degree - 1; i >= 0; i--) {
            result = add(mult(result, x), coeffs[i]);
        }
        return result;

    }
    
    private static int calcInverse(int a) {
        int t = 0;
        int newt = 1;
        int r = 257;
        int newr = a;
        
        while (newr != 0) {
            int quotient = r / newr;
            int tmp = (t - quotient * newt)%257;
            t = newt;
            newt = tmp;
            
            tmp = (r - quotient * newr)%257;
            r = newr;
            newr = tmp;
        }
        
        if (r > 1 && a != 0) {
            throw new RuntimeException("not invertiable");
        }
        
        if (t < 0) {
            t = t + 257;
        }

        return t;
    }

    @Override
    public int inverse(int a) {
        assert (a != 0);
        return invTable[a];
    }

    @Override
    public int getFieldSize() {
        return 257;
    }
}
