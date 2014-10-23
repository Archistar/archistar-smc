package at.archistar.crypto.math;

/**
 *
 * @author andy
 */
public interface GFFactory {
    public GF createHelper();
    
    public GFMatrix createMatrix(int matrix[][]);
}
