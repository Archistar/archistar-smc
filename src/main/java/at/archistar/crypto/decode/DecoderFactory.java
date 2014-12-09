package at.archistar.crypto.decode;

/**
 * The different algorithms need decoders for the recombine step. Those decoders
 * are exchangeable and are examples of externally configured dependencies. A
 * decoder has a state dependent upon its initialization value (as provided by
 * the xValues) which would be typically a constructor parameter.
 * 
 * As Java interfaces neither support static methods (which would allow me to
 * move the factory into the Decoder-class) nor Constructors I've gone the full
 * Factory path.
 */
public interface DecoderFactory {
    
    /** create a new Decoder
     * @param xValues the constant xValues the Decoder was initialized with.
     * @param k (degree+1)/count of the decoded elements
     * @return a new Decoder for the given xValues
     */
    Decoder createDecoder(final int[] xValues, final int k);
}
