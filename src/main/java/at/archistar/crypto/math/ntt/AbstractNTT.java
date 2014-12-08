package at.archistar.crypto.math.ntt;

import at.archistar.crypto.math.GF;
import at.archistar.crypto.math.GFFactory;

/**
 * Helper class for performing NTT operations
 */
public abstract class AbstractNTT {
    
    /** the mathematical field we're doing our operations in */
    protected final GFFactory gffactory;
    
    /** the mathematical field we're doing our operations in */
    protected final GF gf;
    
    /** create a new NTT helper class within field gf
     * 
     * @param gffactory the field within which all operations are performed
     */
    public AbstractNTT(GFFactory gffactory) {
        this.gffactory = gffactory;
        this.gf = gffactory.createHelper();
    }
    
    /**
     * Perform an ntt
     * 
     * @param a incoming data
     * @param w generator
     * @return ntt(a)
     */
    public int[] ntt(int a[], int w) {
        int[] tmp = a.clone();
        inplaceNTT(tmp, w);
        return tmp;
    }

    /**
     * Perform an ntt. This is a higher-performance variant that is performing
     * all operations in-place and does not allocate additional memory
     * 
     * @param a incoming data
     * @param w generator
     */
    public void inplaceNTT(int a[], int w) {
        int[] tmp = ntt(a, w);
        assert(tmp.length == a.length);
        System.arraycopy(tmp, 0, a, 0, a.length);
    }

    /**
     * Perform an intt
     * 
     * @param a incoming data
     * @param w generator
     * @return intt(a)
     */
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
