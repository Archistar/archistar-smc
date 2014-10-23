package at.archistar.crypto.mac;

import java.security.InvalidKeyException;
import java.util.Arrays;
import org.bouncycastle.pqc.math.linearalgebra.GF2nPolynomial;
import org.bouncycastle.pqc.math.linearalgebra.GF2nPolynomialElement;
import org.bouncycastle.pqc.math.linearalgebra.GF2nPolynomialField;

/**
 * a very simple polynomial hash implementation for cevallos
 * 
 * TODO: convert to generic helper
 */
public class PolyHash implements MacHelper {
    
    private final int keylength;
    
    public PolyHash(int keylength) {
        this.keylength = keylength;
    }

    @Override
    public byte[] computeMAC(byte[] data, byte[] key) throws InvalidKeyException {
        
        /* TODO: get field vom polynom? */
        GF2nPolynomialField field = new GF2nPolynomialField(this.keylength);
        
        /* TODO: how to set bits in the polynomial field? */

        GF2nPolynomialElement zero = GF2nPolynomialElement.ZERO(field);
        GF2nPolynomialElement one = GF2nPolynomialElement.ONE(field);
        
        GF2nPolynomial result = new GF2nPolynomial(this.keylength * 8, zero);
        
        /* set b to be the key */
        GF2nPolynomial b = new GF2nPolynomial(this.keylength*8, zero);
        
        int dataPos = 0;
        int inDataPos = 0;

        for (int i = 0; i < this.keylength; i++, inDataPos++) {
            if (inDataPos >= 8) {
                inDataPos = 0;
                dataPos++;
            }
                
            if ((key[dataPos] & (0x1 >> inDataPos)) == 1) {
                b.set(i, one);
            }            
        }
        
        /* set a to be the other part of the key */
        GF2nPolynomial a = new GF2nPolynomial(this.keylength*8, zero);
        
        dataPos = this.keylength;
        inDataPos = 0;
        for (int i = 0; i < this.keylength; i++, inDataPos++) {
            if (inDataPos >= 8) {
                inDataPos = 0;
                dataPos++;
            }
                
            if ((key[dataPos] & (0x1 >> inDataPos)) == 1) {
                a.set(i, one);
            }            
        }

        
        int rowCount = data.length / this.keylength;
        
        dataPos = 0;
        inDataPos = 0;
        
        /* set result's bits to the first keylength elements */
        for (int j = 0; j < this.keylength; j++, inDataPos++) {
            if (inDataPos >= 8) {
                inDataPos = 0;
                dataPos++;
            }
                
            if ((data[dataPos] & (0x1>>inDataPos)) == 1) {
                result.set(j, one);
            }
        }
        
        /* reihenfolge innerhalb des arrays sollte ja wurscht sein */
        for (int i = 1; i < rowCount; i++) {
            GF2nPolynomial next = new GF2nPolynomial(this.keylength * 8, zero);
            for (int j = 0; j < this.keylength; j++, inDataPos++) {
                if (inDataPos >= 8) {
                    inDataPos = 0;
                    dataPos++;
                }
                
                if ((data[dataPos] & (0x1>>inDataPos)) == 1) {
                    next.set(j, one);
                }
            }
            
            result = result.multiply(b).add(next);
        }
        
        /* add rest -> reihenfolge wurscht, sollt also funktionieren */
        if (data.length % this.keylength != 0) {
            GF2nPolynomial next = new GF2nPolynomial(this.keylength * 8, zero);
            
            for (int j = rowCount*this.keylength; j < data.length; j++, inDataPos++) {
                if (inDataPos >= 8) {
                    inDataPos = 0;
                    dataPos++;
                }
                
                if ((data[dataPos] & (0x1>>inDataPos)) == 1) {
                    result.set(j, one);
                }
            }
            result = result.add(next);
        }
        
        /* add a */
        result = result.add(a);
        
        /* extract result into a byte[] array */
        byte[] byteResult = new byte[this.keylength];
        for (int i = 0; i < result.getDegree(); i++) {
            if (result.at(i).isOne()) {
                byteResult[i/8] = (byte)(byteResult[i/8] | (1 >> (i%8)));
            }
        }
        return byteResult;
    }

    @Override
    public boolean verifyMAC(byte[] data, byte[] tag, byte[] key) {
        boolean valid = false;
        
        try {
            byte[] newTag = computeMAC(data, key); // compute tag for the given parameters
            valid = Arrays.equals(tag, newTag); // compare with original tag
        } catch (InvalidKeyException e) {}
        
        return valid;
    }

    @Override
    public int keySize() {
        // a and b
        return this.keylength * 2;
    }
}
