import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

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
	
	public static class InvalidMACException extends Throwable{

		/**
		 * 
		 */
		private static final long serialVersionUID = -2592432690463034492L;
		
	}
	
	private static char[] lookupTable = {'0', '1', '2', '3', '4', '5', '6'
			, '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
	};
	
	/**
	 * Converts bytes to a string of them in hex. Annoyingly, there's no good way to do this.
	 * @param toHex - Bytes for converting.
	 * @return - toHex in hex (base-16).
	 */
	public static String bytesToHex(byte[] toHex) {
		char[] binHex = new char[toHex.length * 2];
		for (int i = 0; i < toHex.length; i++) {
			byte hi = (byte) (toHex[i] & 0xf0);
			byte lo = (byte) (toHex[i] & 0x0f);
			binHex[i] = lookupTable[hi];
			binHex[i+1] = lookupTable[lo];
		}
		return String.copyValueOf(binHex);
	}
	
	/**
	 * Converts hex into an array of bytes.
	 * @param hex - The string to convert.
	 * @return - The bytes as an array of bytes.
	 */
	public static byte[] hexToBytes(String hex) {
		byte[] outputBytes = new byte[hex.length()];
		int ctr = 0;
		byte binCache = 0;
		boolean writeSide = false;
		for (char c: hex.toCharArray()) {
			int valOfHex = Arrays.binarySearch(lookupTable, c);
			if (writeSide) {
				//This hex digit equals the high end of a byte: so write it to the upper 4 bits, then write the byte to the array.
				binCache = (byte) (binCache | (valOfHex & 0xf) << 4);
				outputBytes[ctr] = binCache;
				binCache = 0;
				ctr++;
			}
			else {
				//Write the value of this hex digit to the lower 4 bits of the byte.
				binCache = (byte) (valOfHex & 0xf);
			}
			//Either way, invert which half of the byte we're setting
			writeSide = !writeSide;
		}
		return outputBytes;
	}
}
