package at.archistar.crypto.math;

/**
 *
 * @author andy
 */
public interface GF {
    public int add(int a, int b);   
     
    public int sub(int a, int b);   
          
    public int mult(int a, int b);
    
    public int pow(int a, int b);
    
    public int div(int a, int b);
    
    public int evaluateAt(int coeffs[], int x);
    
    public int inverse(int a);
}
