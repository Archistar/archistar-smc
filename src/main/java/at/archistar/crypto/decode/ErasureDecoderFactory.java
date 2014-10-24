package at.archistar.crypto.decode;

import at.archistar.crypto.math.GFFactory;

/**
 * @author andy
 */
public class ErasureDecoderFactory implements DecoderFactory {
    
    private final GFFactory gffactory;
    
    public ErasureDecoderFactory(GFFactory gffactory) {
        this.gffactory = gffactory;
    }

    @Override
    public Decoder createDecoder(int[] xValues, int k) {
        return new ErasureDecoder(xValues, k, gffactory);
    }
}
