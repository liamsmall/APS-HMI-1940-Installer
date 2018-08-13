/**
 * Advanced Packing Solutions
 * APS HMI [Common Codebase]
 */

package aps.backend;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Handles user authentication.
 * 
 * @author Liam Small
 * @since 13/08/2018
 */
public class Auth {

	private static SecretKeySpec key;

	private static Map<String, String> passwords = new HashMap<String, String>();

	/**
	 * Initialises authentication class ready for encrypting/decrypting texts by
	 * establishing a secret key.
	 * 
	 * @throws AuthException
	 *             Thrown when an error occurs when initialising a secret key.
	 */
	public static void initialise() throws AuthException {
		byte[] salt = new String("APSHMI2018").getBytes();

		// Lower salt decreases startup time, but increases ease of brute force attack
		int iterationCount = 40000;

		// Other key length give java.security.InvalidKeyException : Illegal key size
		int keyLength = 128;
		key = createSecretKey("password".toCharArray(), salt, iterationCount, keyLength);
	}
	
	/**
	 * Validates password entered for requested authentication level.
	 * 
	 * @param password
	 *            Password entered
	 * @param authLevel
	 *            Authentication level requested
	 * @return True/false whether user authenticated successfully
	 * @throws AuthException
	 *             Thrown when an error occurs authenticating
	 */
	public static Boolean matches(String password, AuthLevel authLevel) throws AuthException {
		switch (authLevel) {
		case ADMINISTRATOR:
			return getDecryptedPassword(passwords.get("admin")).equals(password);
		case APS:
			return getDecryptedPassword(passwords.get("aps")).equals(password);
		case MAINTENANCE:
			return getDecryptedPassword(passwords.get("maintenance")).equals(password);
		case MANUFACTURING:
			return getDecryptedPassword(passwords.get("manufacturing")).equals(password);
		case OPERATOR:
			return getDecryptedPassword(passwords.get("operator")).equals(password);
		case UNAUTHORISED:
			return false;
		default:
			return false;
		}
	}

	/**
	 * Creates base passwords to start application.
	 * 
	 * @throws AuthException
	 *             Thrown when an error occurs encrypting passwords
	 */
	public static void createBasePasswords() throws AuthException {
		passwords.put("admin", getEncryptedPassword("admin"));
		passwords.put("aps", getEncryptedPassword("5c6b922a29"));
		passwords.put("maintenance", getEncryptedPassword("maintenance"));
		passwords.put("manufacturing", getEncryptedPassword("manufacturing"));
		passwords.put("operator", getEncryptedPassword("operator"));
	}

	////////////////////////////////////////////////////////////////////////////////
	// SECTION : ENCRYPTION / DECRYPTION
	////////////////////////////////////////////////////////////////////////////////

	/**
	 * Generates a secret key to be used for encryption/decryption of passwords.
	 * 
	 * @param password
	 *            Password to be used for generation of the secret key
	 * @param salt
	 *            Used to make a password hash output unique
	 * @param iterationCount
	 *            Number of iterations on secret key gen
	 * @param keyLength
	 *            Key length used for generation of secret key
	 * @return Secret key specification
	 * @throws AuthException
	 *             Thrown when an error occurs generating a secret key
	 */
	private static SecretKeySpec createSecretKey(char[] password, byte[] salt, int iterationCount, int keyLength) throws AuthException {
		SecretKeyFactory keyFactory = null;
		try {
			keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
		} catch (Exception e) {
			e.printStackTrace();
			AuthExceptionType type = AuthExceptionType.INVALID_KEY_SPEC;
			String message = e.getMessage();
			throw new AuthException(message, type);
		}

		PBEKeySpec keySpec = new PBEKeySpec(password, salt, iterationCount, keyLength);

		SecretKey secretKey = null;
		try {
			secretKey = keyFactory.generateSecret(keySpec);
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
			AuthExceptionType type = AuthExceptionType.INVALID_KEY_SPEC;
			String message = e.getMessage();
			throw new AuthException(message, type);
		}

		return new SecretKeySpec(secretKey.getEncoded(), "AES");
	}
	
	/**
	 * Encodes an array of bytes to a Base64 String.
	 * 
	 * @param bytes
	 *            Bytes to be encoded as a Base64 String
	 * @return Base64 encoding of bytes
	 */
	private static String base64Encode(byte[] bytes) {
		return Base64.getEncoder().encodeToString(bytes);
	}
	
	/**
	 * Decodes Base64 String to bytes array.
	 * 
	 * @param property
	 *            Property to be decoded
	 * @return Bytes array of Base64 String.
	 */
	private static byte[] base64Decode(String property) {
		return Base64.getDecoder().decode(property);
	}
	
	/**
	 * Returns a ciphertext for a given plaintext password.
	 * 
	 * @param plaintext
	 *            Password to be encrypted
	 * @return Ciphertext for given password
	 * @throws AuthException
	 *             Thrown when an error occurs encrypting the password
	 */
	private static String getEncryptedPassword(String plaintext) throws AuthException {
		Cipher pbeCipher;
		try {
			pbeCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			AuthExceptionType type = AuthExceptionType.NO_SUCH_ALGORITHM;
			String message = e.getMessage();
			throw new AuthException(message, type);
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
			AuthExceptionType type = AuthExceptionType.NO_SUCH_PADDING;
			String message = e.getMessage();
			throw new AuthException(message, type);
		}

		try {
			pbeCipher.init(Cipher.ENCRYPT_MODE, key);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			AuthExceptionType type = AuthExceptionType.INVALID_KEY;
			String message = e.getMessage();
			throw new AuthException(message, type);
		}

		AlgorithmParameters parameters = pbeCipher.getParameters();
		IvParameterSpec ivParameterSpec;
		try {
			ivParameterSpec = parameters.getParameterSpec(IvParameterSpec.class);
		} catch (InvalidParameterSpecException e) {
			e.printStackTrace();
			AuthExceptionType type = AuthExceptionType.INVALID_PARAMETER_SPEC;
			String message = e.getMessage();
			throw new AuthException(message, type);
		}

		byte[] cryptoText;
		try {
			cryptoText = pbeCipher.doFinal(plaintext.getBytes("UTF-8"));
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
			AuthExceptionType type = AuthExceptionType.ILLEGAL_BLOCK_SIZE;
			String message = e.getMessage();
			throw new AuthException(message, type);
		} catch (BadPaddingException e) {
			e.printStackTrace();
			AuthExceptionType type = AuthExceptionType.BAD_PADDING;
			String message = e.getMessage();
			throw new AuthException(message, type);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			AuthExceptionType type = AuthExceptionType.UNSUPPORTED_ENCODING;
			String message = e.getMessage();
			throw new AuthException(message, type);
		}

		byte[] iv = ivParameterSpec.getIV();
		return base64Encode(iv) + ":" + base64Encode(cryptoText);
	}

	/**
	 * Returns a plaintext for a given ciphertext.
	 * 
	 * @param ciphertext
	 *            Ciphertext to be decrypted
	 * @return Plaintext from encrypted ciphertext
	 * @throws AuthException
	 *             Thrown when an error occurs decrypting ciphertext
	 */
	private static String getDecryptedPassword(String ciphertext) throws AuthException {
		String iv = ciphertext.split(":")[0];
		String property = ciphertext.split(":")[1];

		Cipher pbeCipher;
		try {
			pbeCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			AuthExceptionType type = AuthExceptionType.NO_SUCH_ALGORITHM;
			String message = e.getMessage();
			throw new AuthException(message, type);
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
			AuthExceptionType type = AuthExceptionType.NO_SUCH_PADDING;
			String message = e.getMessage();
			throw new AuthException(message, type);
		}

		try {
			pbeCipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(base64Decode(iv)));
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			AuthExceptionType type = AuthExceptionType.INVALID_KEY;
			String message = e.getMessage();
			throw new AuthException(message, type);
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
			AuthExceptionType type = AuthExceptionType.INVALID_ALGORITHM_PARAMETER;
			String message = e.getMessage();
			throw new AuthException(message, type);
		}

		try {
			return new String(pbeCipher.doFinal(base64Decode(property)), "UTF-8");
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			AuthExceptionType type = AuthExceptionType.UNSUPPORTED_ENCODING;
			String message = e.getMessage();
			throw new AuthException(message, type);
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
			AuthExceptionType type = AuthExceptionType.ILLEGAL_BLOCK_SIZE;
			String message = e.getMessage();
			throw new AuthException(message, type);
		} catch (BadPaddingException e) {
			e.printStackTrace();
			AuthExceptionType type = AuthExceptionType.BAD_PADDING;
			String message = e.getMessage();
			throw new AuthException(message, type);
		}
	}
	
	////////////////////////////////////////////////////////////////////////////////
	// SECTION : READING FROM / WRITING TO FILE
	////////////////////////////////////////////////////////////////////////////////

	/**
	 * Attempts to read encrypted passwords from a specified filepath.
	 * 
	 * @param filepath
	 *            Path to read passwords from
	 * @throws AuthException
	 *             Exception thrown when an error occurs reading passwords from file
	 */
	public static void readFromFile(String filepath) throws AuthException {
		Properties properties = new Properties();

		try {
			properties.load(new FileInputStream(filepath));
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			AuthExceptionType type = AuthExceptionType.FILE_NOT_FOUND;
			String message = e.getMessage();
			throw new AuthException(message, type);
		} catch (IOException e) {
			e.printStackTrace();
			AuthExceptionType type = AuthExceptionType.FILE_NOT_FOUND;
			String message = e.getMessage();
			throw new AuthException(message, type);
		}

		passwords.put("admin", properties.getProperty("PWD1"));
		passwords.put("aps", properties.getProperty("PWD2"));
		passwords.put("maintenance", properties.getProperty("PWD3"));
		passwords.put("manufacturing", properties.getProperty("PWD4"));
		passwords.put("operator", properties.getProperty("PWD5"));
	}

	/**
	 * Attempts to write the encrypted passwords to a specified filepath.
	 * 
	 * @param filepath
	 *            Path to write passwords to
	 * @throws AuthException
	 *             Exception thrown when an error occurs writing passwords to file
	 */
	public static void writeToFile(String filepath) throws AuthException {
		Properties properties = new Properties();
		properties.setProperty("PWD1", passwords.get("admin"));
		properties.setProperty("PWD2", passwords.get("aps"));
		properties.setProperty("PWD3", passwords.get("maintenance"));
		properties.setProperty("PWD4", passwords.get("manufacturing"));
		properties.setProperty("PWD5", passwords.get("operator"));

		try {
			properties.store(new FileOutputStream(filepath), ""
				+ "------------------------------------------------------------\n"
				+ "ACCESS LEVEL PASSWORDS\n"
				+ "ATTENTION: Changing these passwords will prevent access to the APS HMI. Passwords\n"
				+ "changes should be done using APS HMI, under User Management.\n"
				+ "------------------------------------------------------------\n"
			);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			AuthExceptionType type = AuthExceptionType.FILE_NOT_FOUND;
			String message = e.getMessage();
			throw new AuthException(message, type);
		} catch (IOException e) {
			e.printStackTrace();
			AuthExceptionType type = AuthExceptionType.IO;
			String message = e.getMessage();
			throw new AuthException(message, type);
		}
	}
}
