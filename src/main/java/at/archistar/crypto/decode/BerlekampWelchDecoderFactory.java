package at.archistar.crypto.decode;

/**
 *
 * @author andy
 */
public class BerlekampWelchDecoderFactory implements DecoderFactory {
    
    @Override
    public Decoder createDecoder(int[] xValues, int k) {
        return new BerlekampWelchDecoder(xValues, k);
    }
}
