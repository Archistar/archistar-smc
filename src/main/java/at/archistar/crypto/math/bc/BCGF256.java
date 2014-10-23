package at.archistar.crypto.math.bc;

import at.archistar.crypto.math.GF;
import org.bouncycastle.pqc.math.linearalgebra.GF2mField;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialGF2mSmallM;

/**
 *
 * @author andy
 */
public class BCGF256 implements GF {
    
    private static final GF2mField gf256 = new GF2mField(8, 0x11d); // Galois-Field (x^8 + x^4 + x^3 + x + 1 = 0) / 285
    
    static {
        System.err.println("creating new BCfactory!");
    }


    @Override
    public int add(int a, int b) {
        return gf256.add(a, b);
    }
    
    @Override
    public int div(int a, int b) {
        return gf256.mult(a, gf256.inverse(b));
    }

    @Override
    public int sub(int a, int b) {
        /* add and sub are the same */
        return gf256.add(a, b);
    }

    @Override
    public int mult(int a, int b) {
        return gf256.mult(a, b);
    }
    
    public GF2mField getUnderlyingField() {
        return gf256;
    }

    @Override
    public int pow(int a, int b) {
        return gf256.exp(a, b);
    }
    
    @Override
    public int evaluateAt(int coeffs[], int x) {
        return new PolynomialGF2mSmallM(gf256, coeffs).evaluateAt(x);
    }

    @Override
    public int inverse(int a) {
        return gf256.inverse(a);
    }
}
