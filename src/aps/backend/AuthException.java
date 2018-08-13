/**
 * Advanced Packing Solutions
 * APS HMI [Common Codebase]
 */

package aps.backend;

/**
 * Handles user authentication exceptions.
 * 
 * @author Liam Small
 * @since 13/08/2018
 */
public class AuthException extends Throwable {

	private static final long serialVersionUID = -7089440844818308831L;

	private String message;
	private AuthExceptionType type;

	/**
	 * Constructs an authentication exception.
	 * 
	 * @param message
	 *            Exception message, i.e. what went wrong
	 * @param type
	 *            Type of authentication exception
	 */
	public AuthException(String message, AuthExceptionType type) {
		this.message = message;
		this.type = type;
	}

	/**
	 * Returns the exception message, i.e. what went wrong.
	 * 
	 * @return Exception message
	 */
	public String getMessage() {
		return message;
	}

	/**
	 * Returns the type of authentication exception.
	 * 
	 * @return Type of authentication exception
	 */
	public AuthExceptionType getType() {
		return type;
	}
}
