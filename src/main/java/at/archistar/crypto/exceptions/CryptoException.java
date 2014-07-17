package at.archistar.crypto.exceptions;

/**
 * An Exception thrown {@link helper.ShareMacHelper} and {@link helper.SymmetricEncHelper} to signalize that something went wrong.<br>
 * It acts as a wrapper over the countless internal Java crypto-Exceptions.
 * 
 * @author Elias Frantar
 * @version 2014-7-14
 */
public class CryptoException extends Exception {
	private static final long serialVersionUID = 1L; // unnecessary; just to prevent warning
	
	private String message;
	
	/**
	 * Constructor
	 * @param message the message to deliver with this Exception
	 */
	public CryptoException(String message) {
		this.message = message;
	}
	
	@Override
	public String toString() {
		return "Exception: " + message;
	}
}