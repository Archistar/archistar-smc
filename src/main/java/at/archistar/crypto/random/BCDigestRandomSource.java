/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package at.archistar.crypto.random;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.prng.DigestRandomGenerator;

/**
 *
 * @author andy
 */
public class BCDigestRandomSource implements RandomSource {
    
    private final DigestRandomGenerator drng;
    
    public BCDigestRandomSource() {
        this.drng = new DigestRandomGenerator(new SHA1Digest());
    }

    @Override
    public void fillBytes(byte[] toBeFilled) {
        this.drng.nextBytes(toBeFilled);
    }

    @Override
    public void fillBytesAsInts(int[] toBeFilled) {
        byte[] result = new byte[toBeFilled.length];
        fillBytes(result);
        
        for (int i = 0; i < toBeFilled.length; i++) {
            toBeFilled[i] = result[i] % 256;
        }
    }
    
}
