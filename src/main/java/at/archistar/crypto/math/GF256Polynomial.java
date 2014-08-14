package at.archistar.crypto.math;

/**
 * This class represents a simple polynomial in GF(256) and provides basic functionality like evaluating points.
 * 
 * Since this class uses the methods of {@link GF256}, the same rules apply for using this class.
 *  
 * @author Elias Frantar
 * @version 2014-7-17
 */
public class GF256Polynomial {
    private int[] coeffs; // the coefficients of the polynomial
    private int degree; // coefficients - 1
    
    /**
     * Constructor
     * 
     * @param coeffs the coefficients of the polynomial (numbers in range 0 - 255)<br>
     *        will be interpreted as <i>coeffs[i] * x<sup>i</sup></i> (so the element at index 0 is the constant coefficient)
     */
    public GF256Polynomial(int[] coeffs) {
        this.coeffs = coeffs;
        degree = coeffs.length - 1;
    }
    
    /**
     * Evaluates this polynomial at the given x-value. (f(x))
     * 
     * @param x a number in range 0 - 255
     * @return <i>f(x)</i> (will be in range 0 - 255)
     */
    public int evaluateAt(int x) {
        /* @author flexiprovider */
        int result = coeffs[degree];
        for (int i = degree - 1; i >= 0; i--) {
            result = GF256.add(GF256.mult(result, x), coeffs[i]);
        }
        return result;
    }
}
