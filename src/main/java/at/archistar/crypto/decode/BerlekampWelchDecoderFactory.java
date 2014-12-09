package at.archistar.crypto.decode;

import at.archistar.crypto.math.GFFactory;

/**
 * Factory for creating BerlekampWelchDecoders
 */
public class BerlekampWelchDecoderFactory implements DecoderFactory {
    
    private final GFFactory gffactory;
    
    /**
     * construct a new factory
     * 
     * @param gffactory the field in which we'll be performing operations
     */
    public BerlekampWelchDecoderFactory(final GFFactory gffactory) {
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
        return new BerlekampWelchDecoder(xValues, k, gffactory);
    }
}
