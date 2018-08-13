/**
 * Advanced Packing Solutions
 * APS HMI [Common Codebase]
 */

package aps.backend;

/**
 * Possible states of user access levels.
 * 
 * @author Liam Small
 * @since 13/08/2018
 */
public enum AuthLevel {

	APS,

	ADMINISTRATOR,

	MAINTENANCE,

	MANUFACTURING,

	OPERATOR,

	UNAUTHORISED
}
