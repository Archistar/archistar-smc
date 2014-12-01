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
    
    public abstract int[] ntt(int a[], int w);
    
    public void inplaceNTT(int a[], int w) {
        throw new RuntimeException("not implemented yet");
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
