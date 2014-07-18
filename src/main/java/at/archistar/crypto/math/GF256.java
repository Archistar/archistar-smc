package at.archistar.crypto.math;

/*
 * The operations in this class are meant to be very fast and efficient.
 * The speed is mainly achieved by using lookup-tables for implementing the otherwise very expensive 
 * mult(), div(), pow() and inverse() operations.
 */

/* performing parameter-checks would decrease the performance of this class by around 60%! */

/**
 * <p>This class implements all basic arithmetic operations in a finite field, more precisely a Galois-Field 256 
 * (short <i>GF(256)</i>).</p>
 * 
 * <p>
 * Since GF(256) contains only the numbers 0 - 255:
 * <ul>
 * <li>all methods do only work with parameters in that range
 * <li>all methods will return ints in that range (given that the parameters were valid)
 * <li>you must check yourself (if necessary) if the parameters are in range before calling methods of this class
 * </ul>
 * </p>
 * 
 * <p>For descriptions on how the arithmetics in GF(256) work see: 
 *    <a href="http://en.wikipedia.org/wiki/Finite_field_arithmetic.">http://en.wikipedia.org/wiki/Finite_field_arithmetic.</a></p>
 * 
 * <b>WARNING:</b> The lookup-table implementation could lead to timing attacks on certain microprocessors!
 * 				   So this class may not be suitable for all use-cases. 
 * 				   (but definitively suitable for the <i>Archistar</i>-project)
 * 
 * @author Elias Frantar
 * @version 2014-7-14
 */
public class GF256 {

	private GF256() {} // there should never be any instances of this class
	
	/**
	 * Performs an addition of two numbers in GF(256). (a + b)
	 * 
	 * @param a number in range 0 - 255
	 * @param b number in range 0 - 255
	 * @return the result of <i>a + b</i> in GF(256) (will be in range 0 - 255)
	 */
	public static int add(int a, int b) {
		return a ^ b;
    }
	
	/**
	 * Performs a subtraction of two numbers in GF(256). (a - b)<br>
	 * <b>NOTE:</b> addition and subtraction are the same in GF(256)
	 * 
	 * @param a number in range 0 - 255
	 * @param b number in range 0 - 255
	 * @return the result of <i>a - b</i> in GF(256) (will be in range 0 - 255)
	 */
	public static int sub(int a, int b) {
		return a ^ b;
	}
	
	/**
	 * Performs a multiplication of two numbers in GF(256). (a × b)
	 * 
	 * @param a number in range 0 - 255
	 * @param b number in range 0 - 255
	 * @return the result of <i>a × b</i> in GF(256) (will be in range 0 - 255)
	 */
    public static int mult(int a, int b) {
		if(a == 0 || b == 0) 
    		return 0; // a * 0 = b * 0 = 0 * 0 = 0
    	
    	return ALOG_TABLE[LOG_TABLE[a] + LOG_TABLE[b]];
    }
    
    /**
     * Performs a division of two numbers in GF(256). (a / b)<br>
     * Division by 0 throws an ArithmeticException.
     * 
     * @param a number in range 0 - 255
     * @param b number in range 0 - 255
     * @return the result of <i>a / b</i> in GF(256) (will be in range 0 - 255)
     */
    public static int div(int a, int b) {
		if (b == 0) // a / 0
    		throw new ArithmeticException("Division by 0");
    	if (a == 0) 
    		return 0; // 0 / b = 0

    	return ALOG_TABLE[LOG_TABLE[a] + 255 - LOG_TABLE[b]];
    }
    
    /**
     * Performs an exponentiation of two numbers in GF(256). (a<sup>p</sup>)
     * 
     * @param a number in range 0 - 255
     * @param p the exponent; a number in range 0 - 255
     * @return the result of <i>a<sup>p</sup></i> in GF(256) (will be in range 0 - 255)
     */
    public static int pow(int a, int p) {
		if (a == 0) 
    		return 0;
    	if (a == 1) 
    		return 1;
    	
    	return ALOG_TABLE[p*LOG_TABLE[a] % 255];
    }
    
    /**
     * Computes the inverse of a number in GF(256). (a<sup>-1</sup>)
     * 
     * @param a number in range 0 - 255
     * @return the inverse of a <i>(a<sup>-1</sup>)</i> in GF(256) (will be in range 0 - 255)
     */
    public static int inverse(int a) {
		return ALOG_TABLE[255 - LOG_TABLE[a]];
    }

    /* 
     * lookup tables for the logarithms; required for faster computation different operations
     * @author http://catid.mechafetus.com/news/news.php?view=295
     */
    
	private static final int[] LOG_TABLE = {
	 	   512, 255, 1, 25, 2, 50, 26, 198, 3, 223, 51, 238, 27, 104, 199, 75,
	 	   4, 100, 224, 14, 52, 141, 239, 129, 28, 193, 105, 248, 200, 8, 76, 113,
	 	   5, 138, 101, 47, 225, 36, 15, 33, 53, 147, 142, 218, 240, 18, 130, 69,
	 	   29, 181, 194, 125, 106, 39, 249, 185, 201, 154, 9, 120, 77, 228, 114, 166,
	 	   6, 191, 139, 98, 102, 221, 48, 253, 226, 152, 37, 179, 16, 145, 34, 136,
	 	   54, 208, 148, 206, 143, 150, 219, 189, 241, 210, 19, 92, 131, 56, 70, 64,
	 	   30, 66, 182, 163, 195, 72, 126, 110, 107, 58, 40, 84, 250, 133, 186, 61,
	 	   202, 94, 155, 159, 10, 21, 121, 43, 78, 212, 229, 172, 115, 243, 167, 87,
	 	   7, 112, 192, 247, 140, 128, 99, 13, 103, 74, 222, 237, 49, 197, 254, 24,
	 	   227, 165, 153, 119, 38, 184, 180, 124, 17, 68, 146, 217, 35, 32, 137, 46,
	 	   55, 63, 209, 91, 149, 188, 207, 205, 144, 135, 151, 178, 220, 252, 190, 97,
	 	   242, 86, 211, 171, 20, 42, 93, 158, 132, 60, 57, 83, 71, 109, 65, 162,
	 	   31, 45, 67, 216, 183, 123, 164, 118, 196, 23, 73, 236, 127, 12, 111, 246,
	 	   108, 161, 59, 82, 41, 157, 85, 170, 251, 96, 134, 177, 187, 204, 62, 90,
	 	   203, 89, 95, 176, 156, 169, 160, 81, 11, 245, 22, 235, 122, 117, 44, 215,
	 	   79, 174, 213, 233, 230, 231, 173, 232, 116, 214, 244, 234, 168, 80, 88, 175,
	 	 };
	
	 private static final int[] ALOG_TABLE = {
	 	   1, 2, 4, 8, 16, 32, 64, 128, 29, 58, 116, 232, 205, 135, 19, 38,
	 	   76, 152, 45, 90, 180, 117, 234, 201, 143, 3, 6, 12, 24, 48, 96, 192,
	 	   157, 39, 78, 156, 37, 74, 148, 53, 106, 212, 181, 119, 238, 193, 159, 35,
	 	   70, 140, 5, 10, 20, 40, 80, 160, 93, 186, 105, 210, 185, 111, 222, 161,
	 	   95, 190, 97, 194, 153, 47, 94, 188, 101, 202, 137, 15, 30, 60, 120, 240,
	 	   253, 231, 211, 187, 107, 214, 177, 127, 254, 225, 223, 163, 91, 182, 113, 226,
	 	   217, 175, 67, 134, 17, 34, 68, 136, 13, 26, 52, 104, 208, 189, 103, 206,
	 	   129, 31, 62, 124, 248, 237, 199, 147, 59, 118, 236, 197, 151, 51, 102, 204,
	 	   133, 23, 46, 92, 184, 109, 218, 169, 79, 158, 33, 66, 132, 21, 42, 84,
	 	   168, 77, 154, 41, 82, 164, 85, 170, 73, 146, 57, 114, 228, 213, 183, 115,
	 	   230, 209, 191, 99, 198, 145, 63, 126, 252, 229, 215, 179, 123, 246, 241, 255,
	 	   227, 219, 171, 75, 150, 49, 98, 196, 149, 55, 110, 220, 165, 87, 174, 65,
	 	   130, 25, 50, 100, 200, 141, 7, 14, 28, 56, 112, 224, 221, 167, 83, 166,
	 	   81, 162, 89, 178, 121, 242, 249, 239, 195, 155, 43, 86, 172, 69, 138, 9,
	 	   18, 36, 72, 144, 61, 122, 244, 245, 247, 243, 251, 235, 203, 139, 11, 22,
	 	   44, 88, 176, 125, 250, 233, 207, 131, 27, 54, 108, 216, 173, 71, 142, 1,
	 	   2, 4, 8, 16, 32, 64, 128, 29, 58, 116, 232, 205, 135, 19, 38, 76,
	 	   152, 45, 90, 180, 117, 234, 201, 143, 3, 6, 12, 24, 48, 96, 192, 157,
	 	   39, 78, 156, 37, 74, 148, 53, 106, 212, 181, 119, 238, 193, 159, 35, 70,
	 	   140, 5, 10, 20, 40, 80, 160, 93, 186, 105, 210, 185, 111, 222, 161, 95,
	 	   190, 97, 194, 153, 47, 94, 188, 101, 202, 137, 15, 30, 60, 120, 240, 253,
	 	   231, 211, 187, 107, 214, 177, 127, 254, 225, 223, 163, 91, 182, 113, 226, 217,
	 	   175, 67, 134, 17, 34, 68, 136, 13, 26, 52, 104, 208, 189, 103, 206, 129,
	 	   31, 62, 124, 248, 237, 199, 147, 59, 118, 236, 197, 151, 51, 102, 204, 133,
	 	   23, 46, 92, 184, 109, 218, 169, 79, 158, 33, 66, 132, 21, 42, 84, 168,
	 	   77, 154, 41, 82, 164, 85, 170, 73, 146, 57, 114, 228, 213, 183, 115, 230,
	 	   209, 191, 99, 198, 145, 63, 126, 252, 229, 215, 179, 123, 246, 241, 255, 227,
	 	   219, 171, 75, 150, 49, 98, 196, 149, 55, 110, 220, 165, 87, 174, 65, 130,
	 	   25, 50, 100, 200, 141, 7, 14, 28, 56, 112, 224, 221, 167, 83, 166, 81,
	 	   162, 89, 178, 121, 242, 249, 239, 195, 155, 43, 86, 172, 69, 138, 9, 18,
	 	   36, 72, 144, 61, 122, 244, 245, 247, 243, 251, 235, 203, 139, 11, 22, 44,
	 	   88, 176, 125, 250, 233, 207, 131, 27, 54, 108, 216, 173, 71, 142, 1, 0,
	 	 };
}
