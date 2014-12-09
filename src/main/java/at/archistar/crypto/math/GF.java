package at.archistar.crypto.math;

/**
 * perform mathematic operations within a Galois field
 */
public interface GF {
    
    /** perform addition
     * @return a+b
     */
    public int add(int a, int b);   
     
    /** perform subtraction
     * @return a-b
     */
    public int sub(int a, int b);   
    
    /** perform multiplication
     * @return a * b
     */
    public int mult(int a, int b);
    
    /** perform a^b
     * @return a^b
     */
    public int pow(int a, int b);
    
    /** perform division
     * @return a/b
     */
    public int div(int a, int b);
    
    /** evaluate the polynom at position x
     * 
     * @param coeffs the polynom's coefficients
     * @param x evaluate at position x
     * @return sum over 0..coeffs.length coeffs[i] * x^i
     */
    public int evaluateAt(int coeffs[], int x);
    
    /** calculate inverse element to a
     * @return a^-1
     */
    public int inverse(int a);
    
    /** return the galois field's field size
     * 
     * @return element count
     *
     */
    public int getFieldSize();
}
