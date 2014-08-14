package at.archistar.crypto.decode;

/**
 *
 * @author andy
 */
public class ErasureDecoderFactory implements DecoderFactory {

    @Override
    public Decoder createDecoder(int[] xValues) {
        return new ErasureDecoder(xValues);
    }
}
