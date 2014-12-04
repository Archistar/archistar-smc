package at.archistar.crypto.math;

import at.archistar.crypto.math.GF;
import at.archistar.crypto.math.gf256.GF256;
import at.archistar.crypto.math.gf257.GF257;
import org.junit.Ignore;
import org.junit.Test;

/**
 * do some very simple comparison tests over the different
 * math-implementations
 */
public class MathPerformanceTest {
    
    private final long count = 100000000;
    
    /**
     * test the overhead of our gf-implementations' add
     * 
     * 2014-12-3 seems like we're within +/- 5%
     */
    @Test
    @Ignore("very slow")
    public void testAddPerformance() {
        
        long before, after;
        
        double sumNormalAdd = 0;
        double sumInlineXor = 0;
        double sumInlineModulo = 0;
        double sumGF256AddPoly = 0;
        double sumGF256Add = 0;
        double sumGF257AddPoly = 0;
        
        int a = 4;
        int b = 2;
        int c;
        
        GF gf257 = new GF257();
        GF gf256 = new GF256();
        GF256 nativeGF256 = new GF256();
        
        for (long i = 0; i < count; i++) {
            before = System.currentTimeMillis();
              c = a + b;  
            after = System.currentTimeMillis();

            sumNormalAdd += (after - before);
        }
        
        for (long i = 0; i < count; i++) {
            before = System.currentTimeMillis();
            c = a ^ b;
            after = System.currentTimeMillis();

            sumInlineXor += (after - before);
        }
        
        for (long i = 0; i < count; i++) {
            before = System.currentTimeMillis();
            c = (a + b) % 257;
            after = System.currentTimeMillis();

            sumInlineModulo += (after - before);
        }
        
        for (long i = 0; i < count; i++) {
            before = System.currentTimeMillis();
            c = gf256.add(a, b);
            after = System.currentTimeMillis();

            sumGF256AddPoly += (after - before);
        }

        for (long i = 0; i < count; i++) {
            before = System.currentTimeMillis();
            c = gf257.add(a, b);
            after = System.currentTimeMillis();

            sumGF257AddPoly += (after - before);
        }
        
        for (long i = 0; i < count; i++) {
            before = System.currentTimeMillis();
            c = nativeGF256.add(a, b);
            after = System.currentTimeMillis();

            sumGF256Add += (after - before);
        }
        
        System.out.println("### Add Count: " + count);
        System.out.format("a^b/a+b: %.04f\n", sumInlineXor/sumNormalAdd);
        System.out.format("(a+b) mod 256/a+b: %.04f\n", sumInlineModulo/sumNormalAdd);
        System.out.format("gf(256).add(a,b)/a+b: %.04f\n", sumGF256AddPoly/sumNormalAdd);
        System.out.format("gf(257).add(a,b)/a+b: %.04f\n", sumGF257AddPoly/sumNormalAdd);
        System.out.format("gf256.add(a,b)/a+b: %.04f\n", sumGF256Add/sumNormalAdd);
        System.out.println("");
    }

    /**
     * test the overhead of our gf-implementations' mult
     * 
     * 2014-12-3 seems like we're within +/- 5%
     */
    @Test
    @Ignore("very slow")
    public void testMultPerformance() {
        
        long before, after;
        
        double sumNormalMult = 0;
        double sumInlineMult = 0;
        double sumInlineModulo = 0;
        double sumGF256MultPoly = 0;
        double sumGF256Mult = 0;
        double sumGF257MultPoly = 0;
        
        int a = 4;
        int b = 2;
        int c;
        
        GF gf257 = new GF257();
        GF gf256 = new GF256();
        GF256 nativeGF256 = new GF256();
        
        for (long i = 0; i < count; i++) {
            before = System.currentTimeMillis();
            c = a * b;  
            after = System.currentTimeMillis();

            sumNormalMult += (after - before);
        }
        
        for (long i = 0; i < count; i++) {
            before = System.currentTimeMillis();
            c = GF256.ALOG_TABLE[GF256.LOG_TABLE[a] + GF256.LOG_TABLE[b]];
            after = System.currentTimeMillis();

            sumInlineMult += (after - before);
        }
        
        for (long i = 0; i < count; i++) {
            before = System.currentTimeMillis();
            c = (a * b) % 257;
            after = System.currentTimeMillis();

            sumInlineModulo += (after - before);
        }
        
        for (long i = 0; i < count; i++) {
            before = System.currentTimeMillis();
            c = gf256.mult(a, b);
            after = System.currentTimeMillis();

            sumGF256MultPoly += (after - before);
        }

        for (long i = 0; i < count; i++) {
            before = System.currentTimeMillis();
            c = gf257.mult(a, b);
            after = System.currentTimeMillis();

            sumGF257MultPoly += (after - before);
        }
        
        for (long i = 0; i < count; i++) {
            before = System.currentTimeMillis();
            c = nativeGF256.mult(a, b);
            after = System.currentTimeMillis();

            sumGF256Mult += (after - before);
        }
        
        System.out.println("### Add Count: " + count);
        System.out.format("ALOG[..]/a*b: %.04f\n", sumInlineMult/sumNormalMult);
        System.out.format("(a*b) mod 256/a*b: %.04f\n", sumInlineModulo/sumNormalMult);
        System.out.format("gf(256).mult(a,b)/a*b: %.04f\n", sumGF256MultPoly/sumNormalMult);
        System.out.format("gf(257).mult(a,b)/a*b: %.04f\n", sumGF257MultPoly/sumNormalMult);
        System.out.format("gf256.mult(a,b)/a*b: %.04f\n", sumGF256Mult/sumNormalMult);
        System.out.println("");
    }
}
