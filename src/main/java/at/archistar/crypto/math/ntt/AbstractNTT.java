package at.archistar.crypto.math.ntt;

import at.archistar.crypto.math.GF;

/**
 *
 * @author andy
 */
public abstract class AbstractNTT {
    protected final GF gf;
    
    public AbstractNTT(GF gf) {
        this.gf = gf;
    }
    
    public int[] ntt(int a[], int w) {
        int[] tmp = a.clone();
        inplaceNTT(tmp, w);
        return tmp;
    }
    
    public void inplaceNTT(int a[], int w) {
        int[] tmp = ntt(a, w);
        assert(tmp.length == a.length);
        System.arraycopy(tmp, 0, a, 0, a.length);
    }
    
    public int[] intt(int a[], int w) {
        int n = a.length;
        
        int tmp = gf.div(1, w);
        int[] m = ntt(a, tmp);
        
        for (int i = 0; i < m.length; i++) {
            m[i] = gf.div(m[i], n);
        }
        
        return m;
    }
}
