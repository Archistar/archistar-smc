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
    
    public int[] intt(int a[], int w) {
        int n = a.length;
        int[] m = ntt(a, gf.div(1, w));
        
        for (int i = 0; i < m.length; i++) {
            m[i] = gf.div(m[i], n);
        }
        
        return m;
    }
    
    public int calcUnitySquare(int n) {
        return 256;
    }
}
