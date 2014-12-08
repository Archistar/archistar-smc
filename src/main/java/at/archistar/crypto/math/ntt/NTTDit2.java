package at.archistar.crypto.math.ntt;

import at.archistar.crypto.math.GFFactory;
import at.archistar.crypto.math.gf257.GF257;

/**
 * optimized ntt implemenation
 */
public class NTTDit2 extends AbstractNTT {
    
    private final GF257 gf257;
    
    /** create a new NTT helper class within field gf
     * 
     * @param gffactory the field within which all operations are performed
     */
    public NTTDit2(GFFactory gffactory) {
        super(gffactory);
        if (gf instanceof GF257) {
            this.gf257 = (GF257)gf;
        } else {
            throw new RuntimeException("currently only working with GF257");
        }
    }
    
    /**
     * Perform an ntt. This is a higher-performance variant that is performing
     * all operations in-place and does not allocate additional memory
     * 
     * @param a incoming data
     * @param w generator
     */
    @Override
    public void inplaceNTT(int a[], int w) {
        ntt(a, a.length, log2(a.length), 1);
    }
    
    /**
     * Perform an ntt, result will also be stored within the data parameter
     * 
     * @param data incoming data
     * @param n size of data
     * @param ldn ln^2(data)
     * @param is sign of operation
     * @return ntt(a)
     */
    public int[] ntt(int data[], int n, int ldn, int is) {
        
        assert(n == gf.pow(2, ldn));
        int rn = gf257.primitiveRootOfUnity(n);
        if (is < 0) {
            rn = gf.inverse(rn);
        }
        revbin_permute(data, n);
        for (int ldm = 1; ldm <= ldn; ldm++) {
            
            int m = gf.pow(2, ldm);
            int mh = gf.div(m, 2);
            
            int dw = gf.pow(rn, gf.pow(2, gf.sub(ldn, ldm)));
            
            for (int j = 0, w = 1; j < mh; j++, w = gf.mult(w, dw)) {
                for (int r = 0; r < n; r += m) {
                    int t1 = gf.add(r, j);
                    int t2 = gf.add(t1, mh);
                    
                    int v = gf.mult(data[t2], w);
                    int u = data[t1];
                    
                    data[t1] = gf.add(u, v);
                    data[t2] = gf.sub(u, v);
                }
            }
        }
        
        return data;
    }
    
    private void revbin_permute(int a[], int n) {
        int bitCount = log2(n);
    
        for (int x = 0; x < n - 1; x++) {
            int r = revbin(x, bitCount);
            if (r > x) {
                // swap a[r] with a[r]
                int tmp = a[x];
                a[x] = a[r];
                a[r] = tmp;
            }
        }
    }
    
    private int revbin(int a, int bitCount) {
        return Integer.reverse(a) >>> (64 - bitCount);
    }

    private static int log2(int n){
      if (n <= 0) {
          throw new IllegalArgumentException();
      }
      return 31 - Integer.numberOfLeadingZeros(n);
    }
}
