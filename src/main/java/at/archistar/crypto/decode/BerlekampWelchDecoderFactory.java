package at.archistar.crypto.decode;

/**
 * Factory for creating BerlekampWelchDecoders
 */
public class BerlekampWelchDecoderFactory implements DecoderFactory {

    /**
     * create a new decoder
     *
     * @param xValues our known xValues
     * @param k size of the to-be-solved matrix
     * @return the created decoder
     */
    @Override
    public Decoder createDecoder(final int[] xValues, final int k) {
        return new BerlekampWelchDecoder(xValues, k);
    }
}
