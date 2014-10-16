package at.archistar.crypto.decode;

import at.archistar.crypto.math.GF;

/**
 * @author andy
 */
public class ErasureDecoderFactory implements DecoderFactory {
    
    private final GF gf;
    
    public ErasureDecoderFactory(GF gf) {
        this.gf = gf;
    }

    @Override
    public Decoder createDecoder(int[] xValues, int k) {
        return new ErasureDecoder(xValues, k, gf);
    }
}
