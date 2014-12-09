package at.archistar.crypto.math.gf256;

import at.archistar.crypto.math.GF;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

/**
 * The operations in this class are meant to be very fast and efficient.
 * The speed is mainly achieved by using lookup-tables for implementing the otherwise very expensive 
 * mult(), div(), pow() and inverse() operations.
 *
 * <p>This class implements all basic arithmetic operations in a finite field, more precisely a Galois-Field 256 
 * (short <i>GF(256)</i>).</p>
 * 
 * <p>
 * Since GF(256) contains only the numbers 0 - 255:
 * <ul>
 * <li>all methods do only work with parameters in that range
 * <li>all methods will return ints in that range (given that the parameters were valid)
 * <li>you must check yourself (if necessary) if the parameters are in range before calling methods of this class
 * </ul>
 * </p>
 * 
 * <p>For descriptions on how the arithmetics in GF(256) work see: 
 *    <a href="http://en.wikipedia.org/wiki/Finite_field_arithmetic.">http://en.wikipedia.org/wiki/Finite_field_arithmetic.</a></p>
 * 
 * <b>WARNING:</b> The lookup-table implementation could lead to timing attacks on certain microprocessors!
 *                 So this class may not be suitable for all use-cases. 
 *                 (but definitively suitable for the <i>Archistar</i>-project)
 */
public class GF256 implements GF {
    private static final int GEN_POLY = 0x11D; // a generator polynomial of GF(256)
    
    /** lookup-tables for faster operations. This is public so that I can use
     * it for performance tests
     */
    @SuppressFBWarnings("MS_PKGPROTECT")
    public static final int[] LOG_TABLE = new int[256]; // = log_g(index) (log base g)
    
    /** lookup-tables for faster operations. This is public so that I can use
     * it for performance tests
     */
    @SuppressFBWarnings("MS_PKGPROTECT")
    public static final int[] ALOG_TABLE = new int[1025]; // = pow(g, index); 512 * 2 + 1
    
    /* 
     * initialize the lookup tables
     * basis for writing this code: http://catid.mechafetus.com/news/news.php?view=295
     */
    static {
        LOG_TABLE[0] = 512;
        ALOG_TABLE[0] = 1;
                
        for (int i = 1; i < 255; i++) {
            int next = ALOG_TABLE[i - 1] * 2;
            if (next >= 256) {
                next ^= GEN_POLY;
            }
            
            ALOG_TABLE[i] = next;
            LOG_TABLE[ALOG_TABLE[i]] = i;
        }
        
        ALOG_TABLE[255] = ALOG_TABLE[0];
        LOG_TABLE[ALOG_TABLE[255]] = 255;
        
        for (int i = 256; i < 510; i++) { // 2 * 255
            ALOG_TABLE[i] = ALOG_TABLE[i % 255];
        }
        
        ALOG_TABLE[510] = 1; // 2 * 255
        
        for (int i = 511; i < 1020; i++) { // 2 * 255 + 1; 4 * 255
            ALOG_TABLE[i] = 0;
        }
    }
    
    /* arithmetic operations */
    
    /**
     * Performs an addition of two numbers in GF(256). (a + b)
     * 
     * @param a number in range 0 - 255
     * @param b number in range 0 - 255
     * @return the result of <i>a + b</i> in GF(256) (will be in range 0 - 255)
     */
    @Override
    public int add(int a, int b) {
        return a ^ b;
    }
    
    /**
     * Performs a subtraction of two numbers in GF(256). (a - b)<br>
     * <b>NOTE:</b> addition and subtraction are the same in GF(256)
     * 
     * @param a number in range 0 - 255
     * @param b number in range 0 - 255
     * @return the result of <i>a - b</i> in GF(256) (will be in range 0 - 255)
     */
    @Override
    public int sub(int a, int b) {
        return a ^ b;
    }
    
    /**
     * Performs a multiplication of two numbers in GF(256). (a × b)
     * 
     * @param a number in range 0 - 255
     * @param b number in range 0 - 255
     * @return the result of <i>a × b</i> in GF(256) (will be in range 0 - 255)
     */
    @Override
    public int mult(int a, int b) {
        return ALOG_TABLE[LOG_TABLE[a] + LOG_TABLE[b]];
    }
    
    /**
     * Performs an exponentiation of two numbers in GF(256). (a<sup>p</sup>)
     * 
     * @param a number in range 0 - 255
     * @param p the exponent; a number in range 0 - 255
     * @return the result of <i>a<sup>p</sup></i> in GF(256) (will be in range 0 - 255)
     */
    @Override
    public int pow(int a, int p) {
        // The use of 512 for LOG[0] and the all-zero last half of ALOG cleverly
        // avoids testing 0 in mult, but can't survive arbitrary p*...%255 here.
        if (0 == a && 0 != p) {
          return 0;
        }
        return ALOG_TABLE[p*LOG_TABLE[a] % 255];
    }
    
    /**
     * Computes the inverse of a number in GF(256). (a<sup>-1</sup>)
     * 
     * @param a number in range 0 - 255
     * @return the inverse of a <i>(a<sup>-1</sup>)</i> in GF(256) (will be in range 0 - 255)
     */
    @Override
    public int inverse(int a) {
        return ALOG_TABLE[255 - (LOG_TABLE[a] % 255)];
    }
    
    @Override
    public int div(int a, int b) {
        if (b == 0) { // a / 0
            throw new ArithmeticException("Division by 0");
        }

        return ALOG_TABLE[LOG_TABLE[a] + 255 - LOG_TABLE[b]];
    }
    
    @Override
    public int evaluateAt(int coeffs[], int x) {
        int degree = coeffs.length -1;
        
        /* @author flexiprovider */
        int result = coeffs[degree];
        for (int i = degree - 1; i >= 0; i--) {
            result = add(mult(result, x), coeffs[i]);
        }
        return result;
    }

    @Override
    public int getFieldSize() {
        return 256;
    }
}
