package at.archistar.crypto.mac;

import at.archistar.crypto.math.GF;
import java.security.InvalidKeyException;
import java.util.Arrays;

/**
 * a very simple polynomial hash implementation for cevallos
 * 
 * TODO: convert to generic helper
 */
public class PolyHash implements MacHelper {
    
    private final int keylength;
    
    private final GF gf;
    
    public PolyHash(int keylength, GF gf) {
        this.keylength = keylength;
        this.gf = gf;
    }
    
    private static int[] createIntArrayFromByte(byte[] a) {
        int[] b = new int[a.length];
        for (int i = 0; i < a.length; i++) {
            b[i] = a[i];
        }
        return b;
    }

    @Override
    public byte[] computeMAC(byte[] data, byte[] key) throws InvalidKeyException {
        
        assert(this.keylength * 2 == key.length);
        
        int b[] = createIntArrayFromByte(Arrays.copyOf(key, this.keylength));
        
        /* set a to be the other part of the key */
        int[] a = createIntArrayFromByte(Arrays.copyOfRange(key, this.keylength, key.length));
        
        /* set result's bits to the first keylength elements */
        int[] result = createIntArrayFromByte(Arrays.copyOf(data, this.keylength));
        
        int rowCount = data.length / this.keylength;
        
        /* reihenfolge innerhalb des arrays sollte ja wurscht sein */
        for (int i = 1; i < rowCount; i++) {
            int[] next = createIntArrayFromByte(Arrays.copyOfRange(data, i*this.keylength, (i+1)*this.keylength));
            result = multiply(result, add(b, next));
        }
        
        /* add rest -> reihenfolge wurscht, sollt also funktionieren */
        if (data.length % this.keylength != 0) {
            int[] next = createIntArrayFromByte(Arrays.copyOfRange(data, rowCount*this.keylength, data.length));
            
            /* expand to keylength */
            next = Arrays.copyOf(next, keylength);
            System.err.println(""+ result.length + " vs " + next.length);
            result = add(result, next);
        }
        
        /* add a */
        System.err.println(""+ result.length + " vs " + a.length);
        result = add(result, a);
        
        /* extract result into a byte[] array */
        byte[] byteResult = new byte[this.keylength];
        for (int i = 0; i < result.length; i++) {
            byteResult[i] = (byte)result[i];
        }
        return byteResult;
    }
    
    private int[] add(int[] a, int[] b)
    {
        
        // TODO: optimize
        //assert(a.length == b.length);
        
        int[] result, addend;
        if (a.length < b.length)
        {
            result = new int[b.length];
            System.arraycopy(b, 0, result, 0, b.length);
            addend = a;
        }
        else
        {
            result = new int[a.length];
            System.arraycopy(a, 0, result, 0, a.length);
            addend = b;
        }

        for (int i = addend.length - 1; i >= 0; i--)
        {
            result[i] = gf.add(result[i], addend[i]);
        }

        return result;
    }
    
      private int[] multiply(int[] a, int[] b)
    {
        int[] mult1, mult2;
        if (computeDegree(a) < computeDegree(b))
        {
            mult1 = b;
            mult2 = a;
        }
        else
        {
            mult1 = a;
            mult2 = b;
        }

        mult1 = normalForm(mult1);
        mult2 = normalForm(mult2);

        if (mult2.length == 1)
        {
            return multWithElement(mult1, mult2[0]);
        }

        int d1 = mult1.length;
        int d2 = mult2.length;
        int[] result = new int[d1 + d2 - 1];

        if (d2 != d1)
        {
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
      
       private static int[] normalForm(int[] a)
    {
        int d = computeDegree(a);

        // if a is the zero polynomial
        if (d == -1)
        {
            // return new zero polynomial
            return new int[1];
        }

        // if a already is in normal form
        if (a.length == d + 1)
        {
            // return a clone of a
            return Arrays.copyOf(a, a.length);
        }

        // else, reduce a
        int[] result = new int[d + 1];
        System.arraycopy(a, 0, result, 0, d + 1);
        return result;
    }
      
       private int[] multWithElement(int[] a, int element)
    {
        int degree = computeDegree(a);
        if (degree == -1 || element == 0)
        {
            return new int[keylength];
        }

        if (element == 1)
        {
            return Arrays.copyOf(a, a.length);
        }

        int[] result = new int[degree + 1];
        for (int i = degree; i >= 0; i--) {
            result[i] = gf.mult(a[i], element);
        }

        return result;
    }
      
    private static int computeDegree(int[] a)
    {
        int degree;
        for (degree = a.length - 1; degree >= 0 && a[degree] == 0; degree--)
        {
            ;
        }
        return degree;
    }
    
     private static int[] multWithMonomial(int[] a, int k)
    {
        int d = computeDegree(a);
        if (d == -1)
        {
            return new int[1];
        }
        int[] result = new int[d + k + 1];
        System.arraycopy(a, 0, result, k, d + 1);
        return result;
    }


    @Override
    public boolean verifyMAC(byte[] data, byte[] tag, byte[] key) {
        boolean valid = false;
        
        try {
            byte[] newTag = computeMAC(data, key); // compute tag for the given parameters
            valid = Arrays.equals(tag, newTag); // compare with original tag
        } catch (InvalidKeyException e) {}
        
        return valid;
    }

    @Override
    public int keySize() {
        // a and b
        return this.keylength * 2;
    }
}
