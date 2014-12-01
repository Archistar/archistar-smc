package at.archistar.crypto.math.ntt;

import at.archistar.crypto.math.GF;
import at.archistar.crypto.math.gf257.GF257;

/**
 * @author andy
 */
public class NTTDit2 extends AbstractNTT {
    
    private final GF257 gf257;
    
    public NTTDit2(GF gf) {
        super(gf);
        if (gf instanceof GF257) {
            this.gf257 = (GF257)gf;
        } else {
            throw new RuntimeException("currently only working with GF257");
        }
    }
    
    @Override
    public int[] ntt(int a[], int w) {
        /* TODO: implemenent an overwriting version, so we can get rid of the memory copy */
        int[] tmp = a.clone();
        return ntt(tmp, tmp.length, log2(tmp.length), 1);
    }
    
    @Override
    public void inplaceNTT(int a[], int w) {
        ntt(a, a.length, log2(a.length), 1);
    }
    
    public int[] ntt(int data[], int n, int ldn, int is) {
        
        assert(n == gf.pow(2, ldn));
        int rn = gf257.primitiveRootOfUnity(n);
        if (is < 0) {
            // TODO: how is -1? isn't this the inverse element?
            // rn = gf.pow(rn, -1);
            rn = gf.inverse(rn);
        }
        revbin_permute(data, n);
        for (int ldm = 1; ldm <= ldn; ldm++) {
            
            int m = gf.pow(2, ldm);
            int mh = gf.div(m, 2);
            
            int dw = gf.pow(rn, gf.pow(2, gf.sub(ldn, ldm)));
            // in c++: mod::root2pow( (int) (is>0 ? ldm : -ldm));
            // does this mean that i need the n-th root for n.. (1..8)
            
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
        // TODO is this < or <=
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
    
    /* do a bitwise reverse (in gf(n)?) */
    private int revbin(int a, int bitCount) {
        return Integer.reverse(a) >>> (64 - bitCount);
    }

    @Override
    public int[] intt(int[] a, int w) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
    private static int log2(int n){
      if (n <= 0) {
          throw new IllegalArgumentException();
      }
      return 31 - Integer.numberOfLeadingZeros(n);
    }
}
