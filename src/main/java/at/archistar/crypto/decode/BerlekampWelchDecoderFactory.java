package at.archistar.crypto.decode;

import at.archistar.crypto.math.GF;

/**
 *
 * @author andy
 */
public class BerlekampWelchDecoderFactory implements DecoderFactory {
    
    private final GF gf;
    
    public BerlekampWelchDecoderFactory(GF gf) {
        this.gf = gf;
    }
    
    @Override
    public Decoder createDecoder(int[] xValues, int k) {
        return new BerlekampWelchDecoder(xValues, k, gf);
    }
}
