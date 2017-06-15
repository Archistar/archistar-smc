package at.archistar.crypto.decode;

/**
 * Factory for creating ErasureDecoders
 */
public class ErasureDecoderFactory implements DecoderFactory {

    /**
     * create a new decoder
     *
     * @param xValues our known xValues
     * @param k size of the to-be-solved matrix
     * @return the created decoder
     */
    @Override
    public Decoder createDecoder(final int[] xValues, final int k) {
        return new ErasureDecoder(xValues, k);
    }
}
