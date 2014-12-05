package at.archistar.crypto.math;

/**
 * perform mathematic operations within a Galois field
 */
public interface GF {
    
    /** perform addition */
    public int add(int a, int b);   
     
    /** perform subtraction */
    public int sub(int a, int b);   
    
    /** perform multiplication */
    public int mult(int a, int b);
    
    /** perform a^b */
    public int pow(int a, int b);
    
    /** perform division */
    public int div(int a, int b);
    
    /** evaluate the polynom at position x
     * 
     * @param coeffs the polynom's coefficients
     * @param x evaluate at position x
     */
    public int evaluateAt(int coeffs[], int x);
    
    /** calculate inverse element to a */
    public int inverse(int a);
    
    /** return the galois field's field size */
    public int getFieldSize();
}
