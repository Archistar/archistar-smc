/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
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
    
    public int evaluateAt(int coeffs[], int x);
}
