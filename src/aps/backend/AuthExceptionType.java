/**
 * Advanced Packing Solutions
 * APS HMI [Common Codebase]
 */

package aps.backend;

/**
 * Possible authentication exception types.
 * 
 * @author Liam Small
 * @since 13/08/2018
 */
public enum AuthExceptionType {

	BAD_PADDING,

	EXCEPTION,

	FILE_NOT_FOUND,

	ILLEGAL_BLOCK_SIZE,

	INVALID_ALGORITHM_PARAMETER,

	INVALID_KEY,

	INVALID_KEY_SPEC,

	INVALID_PARAMETER_SPEC,

	IO,

	NO_SUCH_ALGORITHM,

	NO_SUCH_PADDING,

	UNSUPPORTED_ENCODING
}
