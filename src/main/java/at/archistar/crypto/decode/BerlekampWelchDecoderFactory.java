package at.archistar.crypto.decode;

import at.archistar.crypto.math.GFFactory;

/**
 *
 * @author andy
 */
public class BerlekampWelchDecoderFactory implements DecoderFactory {
    
    private final GFFactory gffactory;
    
    public BerlekampWelchDecoderFactory(GFFactory gffactory) {
        this.gffactory = gffactory;
    }
    
    @Override
    public Decoder createDecoder(int[] xValues, int k) {
        return new BerlekampWelchDecoder(xValues, k, gffactory);
    }
}
