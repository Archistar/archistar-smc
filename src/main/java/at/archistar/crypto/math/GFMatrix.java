package at.archistar.crypto.math;

/**
 *
 * @author andy
 */
public interface GFMatrix {
    public int[] rightMultiply(int vec[]);
    
    public GFMatrix inverseElimDepRows();
    
    public GFMatrix inverse();
    
    public int getNumRows();
}
