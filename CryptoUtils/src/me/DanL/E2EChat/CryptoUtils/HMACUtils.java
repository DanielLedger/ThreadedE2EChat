package me.DanL.E2EChat.CryptoUtils;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class HMACUtils {
	/**
	 * Creates a Hashed Message Authentication Code using SHA256 as the hash function.
	 * @param data - The data to verify.
	 * @param key - The key to verify it with. Note that HMAC(data, key) != HMAC(key, data).
	 * @return - A 32 byte MAC of the given data with the given key.
	 */
	public static byte[] hmac(byte[] data, byte[] key) {
		try {
			Mac hmacCalc = Mac.getInstance("HmacSHA256");
			SecretKeySpec macKey = new SecretKeySpec(key, "HmacSHA256");
			hmacCalc.init(macKey);
			hmacCalc.update(data);
			return hmacCalc.doFinal();
		} catch (NoSuchAlgorithmException e) {
			//This is a bug if this happens, so fix it.
			e.printStackTrace();
			return null;
		} catch (InvalidKeyException e) {
			//Also a bug, so fix if this happens
			e.printStackTrace();
			return null;
		}
		
	}
	
	/**
	 * Calculates HMAC of some data. See {@link HMACUtils#hmac(byte[], byte[])}
	 * @param data
	 * @param key
	 * @return A hex representation of the HMAC.
	 */
	public static String hexHmac(byte[] data, byte[] key) {
		return BinaryUtils.bytesToHex(HMACUtils.hmac(data, key));
	}
	
	/**
	 * Compares a and b such that they are not vulnerable to timing attacks.
	 * Note that this could still leak information about the length of the arrays.
	 * @param a
	 * @param b
	 * @return - True if the byte strings are identical, False if not.
	 */
	private static boolean slowCmp(byte[] a, byte[] b) {
		if (a.length != b.length) {
			return false; //Although this isn't constant-time, you already knew the MAC was 32 bytes in this case, so it doesn't matter.
		}
		int diffSum = 0;
		for (int i = 0; i<a.length; i++) {
			diffSum += a[i] ^ b[i]; //If a[i] == b[i], a[i] ^ b[i] = 0, otherwise it won't be.
		}
		return diffSum == 0;
	}
	
	/**
	 * Verifies that the MAC given matches the data. Using a timing-independant way of comparing the data.
	 * @param data - The data to MAC.
	 * @param key - The key to use to generate the MAC.
	 * @param mac - The MAC we're verifying.
	 * @throws InvalidMACException - If the MAC does not authenticate the data we've been given.
	 * 
	 */
	public static void verifyHmac(byte[] data, byte[] key, byte[] mac) throws InvalidMACException {
		byte[] dataMac = HMACUtils.hmac(data, key);
		if (HMACUtils.slowCmp(dataMac, mac)) {
			return; //We're fine.
		}
		else {
			throw new InvalidMACException();
		}
	}
	
	public static void verifyHexHmac(byte[] data, byte[] key, String mac) throws InvalidMACException {
		verifyHmac(data, key, BinaryUtils.hexToBytes(mac));
	}
	
	public static class InvalidMACException extends Throwable{

		/**
		 * 
		 */
		private static final long serialVersionUID = -2592432690463034492L;
		
	}
}
