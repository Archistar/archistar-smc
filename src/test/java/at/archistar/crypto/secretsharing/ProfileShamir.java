/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package at.archistar.crypto.secretsharing;

import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.decode.ErasureDecoderFactory;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.math.GFFactory;
import at.archistar.crypto.math.gf257.GF257Factory;
import at.archistar.crypto.math.ntt.NTTDit2;
import at.archistar.crypto.random.FakeRandomSource;
import at.archistar.crypto.random.RandomSource;
import org.junit.Test;

/**
 *
 * @author andy
 */
public class ProfileShamir {
    
    private static byte[] createArray(int size) {
        byte[] result = new byte[size];

        for (int i = 0; i < size; i++) {
            result[i] = 1;
        }

        return result;
    }

    final int n = 4;
    final int k = 3;
    byte[] secrets = createArray(4 * 1024 * 1024);
    RandomSource rng = new FakeRandomSource();
    GFFactory gffactory = new GF257Factory();
    int generator = 3;
    DecoderFactory decoderFactory = new ErasureDecoderFactory(gffactory);
    NTTDit2 ntt = new NTTDit2(gffactory.createHelper());
            
    @Test
    public void testProfile() throws WeakSecurityException {
        
        BaseSecretSharing ss = new NTTShamirPSS(n, k, generator, gffactory, rng, ntt, decoderFactory);
        
        for (int i = 0; i < 10; i++) {
            ss.share(secrets);
        }
    }
}
