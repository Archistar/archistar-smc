package at.archistar.crypto.decode;

/**
 *
 * @author andy
 */
public class ErasureDecoderFactory implements DecoderFactory {

    @Override
    public Decoder createDecoder(int[] xValues, int k) {
        return new ErasureDecoder(xValues, k);
    }
}
