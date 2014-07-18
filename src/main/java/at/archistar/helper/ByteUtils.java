package at.archistar.helper;

/**
 * Provides some little utility for converting a (in Java signed) byte to an unsigned Integer.
 * 
 * @author Elias Frantar
 * @version 2014-7-18
 */
public class ByteUtils {
	private ByteUtils() {} // we don't want any instances of that class
	
	/**
	 * Converts the signed byte to its unsigned integer representation.
	 * @param b the byte to convert
	 * @return the corresponding unsigned integer in range 0 - 255
	 */
	public static int toUnsignedByte(byte b) {
		return (int) (b & 0xFF);
	}
}
