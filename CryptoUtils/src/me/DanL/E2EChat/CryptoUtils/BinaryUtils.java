package me.DanL.E2EChat.CryptoUtils;

import java.security.SecureRandom;

/**
 * Assorted utility functions for manipulating binary etc.
 * @author daniel
 *
 */
public class BinaryUtils {
	/**
	 * Generates cryptographically secure random bytes, primarily for Argon2 but can be used anywhere.
	 * @param length - The number of bytes to generate.
	 * @return - length cryptographically secure bytes.
	 */
	public static byte[] getSalt(int length) {
		SecureRandom secRng = new SecureRandom();
		return secRng.generateSeed(length);
	}
	
	private static final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();
	/**
	 * Convert a byte array into a hexadecimal string
	 * @param bytes
	 * @return
	 */
	public static String bytesToHex(byte[] bytes) {
	    char[] hexChars = new char[bytes.length * 2];
	    for (int j = 0; j < bytes.length; j++) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = HEX_ARRAY[v >>> 4];
	        hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
	    }
	    return new String(hexChars);
	}
	
	/**
	 * Convert a hex string into a byte array.
	 * @param s
	 * @return
	 */
	public static byte[] hexToBytes(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}
}
