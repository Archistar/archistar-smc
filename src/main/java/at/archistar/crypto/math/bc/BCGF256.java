package at.archistar.crypto.math.bc;

import at.archistar.crypto.math.GF;
import org.bouncycastle.pqc.math.linearalgebra.GF2mField;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialGF2mSmallM;

/**
 * perform mathematic operations in GF(2^8) utilizing the bouncy castle
 * mathematic library
 */
public class BCGF256 implements GF {
    
    private static final GF2mField GF256 = new GF2mField(8, 0x11d); // Galois-Field (x^8 + x^4 + x^3 + x + 1 = 0) / 285
    
    @Override
    public int add(int a, int b) {
        return GF256.add(a, b);
    }
    
    @Override
    public int div(int a, int b) {
        return GF256.mult(a, GF256.inverse(b));
    }

    @Override
    public int sub(int a, int b) {
        /* add and sub are the same */
        return GF256.add(a, b);
    }

    @Override
    public int mult(int a, int b) {
        return GF256.mult(a, b);
    }
    
    /**
     * @return get the underlying (bouncy castle specific) field
     */
    GF2mField getUnderlyingField() {
        return GF256;
    }

    @Override
    public int pow(int a, int b) {
        return GF256.exp(a, b);
    }
    
    @Override
    public int evaluateAt(int coeffs[], int x) {
        return new PolynomialGF2mSmallM(GF256, coeffs).evaluateAt(x);
    }

    @Override
    public int inverse(int a) {
        return GF256.inverse(a);
    }

    @Override
    public int getFieldSize() {
        return 256;
    }
}
