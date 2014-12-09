package at.archistar.crypto.decode;

import at.archistar.crypto.math.GFFactory;

/**
 * Factory for creating ErasureDecoders
 */
public class ErasureDecoderFactory implements DecoderFactory {
    
    private final GFFactory gffactory;
    
    /**
     * construct a new factory
     * 
     * @param gffactory the field in which we'll be performing operations
     */
    public ErasureDecoderFactory(final GFFactory gffactory) {
        this.gffactory = gffactory;
    }

    /**
     * create a new decoder
     * 
     * @param xValues our known xValues
     * @param k size of the to-be-solved matrix
     * @return the created decoder
     */
    @Override
    public Decoder createDecoder(final int[] xValues, final int k) {
        return new ErasureDecoder(xValues, k, gffactory);
    }
}
