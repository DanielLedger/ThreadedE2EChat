package me.DanL.E2EChat.CryptoUtils;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Contains a series of utility methods for various AES constructs (specifically AES-CBC and AES-GCM)
 * 
 * AES-CBC is used for key encryption, AES-GCM is used for message encryption.
 * 
 * @author daniel
 */
public class AES {
	/**
	 * Encrypts the data with AES-CBC. Data is automatically padded and unpadded.
	 * Please note that this does not authenticate data in any way unless you add some kind of MAC.
	 * Use AES-GCM for authenticated cryptography.
	 * @param key - The encryption key. Must be 32 bytes long.
	 * @param iv - The IV for encryption. Doesn't need to be kept secret, but must be unique and random.
	 * @param data - The data to encrypt.
	 * @return - The data encrypted with the key-iv pair.
	 * @throws InvalidKeyException - If the key is the wrong size.
	 */
	public static byte[] encryptCBC(byte[] key, byte[] iv, byte[] data) throws InvalidKeyException {
		SecretKeySpec sks = new SecretKeySpec(key, "AES");
		try {
			Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
			IvParameterSpec ivp = new IvParameterSpec(iv);
			c.init(Cipher.ENCRYPT_MODE, sks, ivp);
			return c.doFinal(data);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			//This is bad.
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			//???
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			//???
			e.printStackTrace();
		} catch (BadPaddingException e) {
			//???
			e.printStackTrace();
		}
		return null;
		
	}
	
	/**
	 * Decrypts the data with AES-CBC. Data is automatically padded and unpadded.
	 * Please note that this does not authenticate data in any way unless you add some kind of MAC.
	 * Use AES-GCM for authenticated cryptography.
	 * @param key - The encryption key. Must be 32 bytes long.
	 * @param iv - The IV for encryption. Doesn't need to be kept secret, but must be unique and random.
	 * @param data - The data to encrypt.
	 * @return - The data encrypted with the key-iv pair.
	 * @throws InvalidKeyException - If the key is the wrong size.
	 */
	public static byte[] decryptCBC(byte[] key, byte[] iv, byte[] data) throws InvalidKeyException {
		SecretKeySpec sks = new SecretKeySpec(key, "AES");
		try {
			Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
			IvParameterSpec ivp = new IvParameterSpec(iv);
			c.init(Cipher.DECRYPT_MODE, sks, ivp);
			return c.doFinal(data);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			//This is bad.
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			//???
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			//???
			e.printStackTrace();
		} catch (BadPaddingException e) {
			//???
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * Encrypts the data with AES-GCM. The last 128 bits of the ciphertext are
	 * the GCM tag, which verifies that the ciphertext hasn't been tampered with.
	 * @param key - Encryption key.
	 * @param iv - Encryption IV. NEVER reuse an IV-key pairing.
	 * @param data - The data to encrypt.
	 * @return GCM(data)||auth tag
	 * @throws InvalidKeyException 
	 */
	public static byte[] encryptGCM(byte[] key, byte[] iv, byte[] data) throws InvalidKeyException {
		SecretKeySpec sks = new SecretKeySpec(key, "AES");
		try {
			Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
			GCMParameterSpec ivp = new GCMParameterSpec(128, iv);
			c.init(Cipher.ENCRYPT_MODE, sks, ivp);
			return c.doFinal(data);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			//This is bad.
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			//???
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			//???
			e.printStackTrace();
		} catch (BadPaddingException e) {
			//???
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * Decrypts the data with AES-GCM. The last 128 bits of the ciphertext are
	 * the GCM tag, which verifies that the ciphertext hasn't been tampered with.
	 * 
	 * The behaviour of what happens when a tag is invalid is a little hard to define,
	 * but if you write your code such that it can cope with either the function silently returning null
	 * or throwing an AEADBadTagException you'll be fine.
	 * 
	 * @param key - Decryption key.
	 * @param iv - Decryption IV. NEVER reuse an IV-key pairing.
	 * @param data - The ciphertext to decrypt.
	 * @return GCM(data)||auth tag
	 * @throws InvalidKeyException 
	 */
	public static byte[] decryptGCM(byte[] key, byte[] iv, byte[] data) throws InvalidKeyException, AEADBadTagException {
		SecretKeySpec sks = new SecretKeySpec(key, "AES");
		try {
			Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
			GCMParameterSpec ivp = new GCMParameterSpec(128, iv);
			c.init(Cipher.DECRYPT_MODE, sks, ivp);
			return c.doFinal(data);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			//This is bad.
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			//???
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			//???
			e.printStackTrace();
		} catch (BadPaddingException e) {
			//???
			e.printStackTrace();
		}
		return null;
	}
}
