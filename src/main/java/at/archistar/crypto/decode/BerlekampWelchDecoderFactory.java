package at.archistar.crypto.decode;

/**
 *
 * @author andy
 */
public class BerlekampWelchDecoderFactory implements DecoderFactory {
    
    private int order = 0;

    public BerlekampWelchDecoderFactory(int order) {
        this.order = order;
    }
    
    @Override
    public Decoder createDecoder(int[] xValues) {
        return new BerlekampWelchDecoder(order, xValues);
    }
}
