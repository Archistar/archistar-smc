package at.archistar.crypto.math.ntt;

import at.archistar.crypto.math.GFFactory;

/**
 * Helper class for performing NTT operations
 */
public class NTTTextbook extends AbstractNTT {
    
    /** initialize helper class
     * 
     * @param gffactory the mathematical field within which all operations should be
            *           performed
     */
    public NTTTextbook(GFFactory gffactory) {
        super(gffactory);
    }
    
    /**
     * Perform an ntt
     * 
     * @param a incoming data
     * @param w generator
     * @return ntt(a)
     */
    @Override
    public int[] ntt(int a[], int w) {
        int n = a.length;
        
        if (n == 1) {
            return a;
        } else if (n%2 == 0) {
            return new NTTSlow(gffactory).ntt(a, w);
        } else {
                        
            int[] even = new int[n/2+1];
            int[] odd = new int[n/2];
            int[] combined = new int[n];
            
            /* create even */
            for (int i = 0; i < n; i += 2) {
                even[i/2] = a[i];
            }
            even = ntt(even, gf.pow(w, 2));

            /* create odd */
            for (int i = 1; i < n; i += 2) {
                odd[i/2] = a[i];
            }
            odd = ntt(odd, gf.pow(w, 2));
            
            for (int i = 0; i < n; i++) {
                combined[i] = gf.add(even[i], gf.mult(gf.pow(w, i), odd[i]));
                int exp = gf.add(gf.div(n, 2), i);
                combined[i + n/2] = gf.add(even[i], gf.mult(gf.pow(w, exp), odd[i]));
            }
            
            return combined;
        }
    }
}
