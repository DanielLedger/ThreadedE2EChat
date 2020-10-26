package me.DanL.E2EChat.CryptoUtils;

import java.security.InvalidKeyException;

import javax.crypto.AEADBadTagException;

public class Main {
	
	public static void main(String[] args) throws InvalidKeyException {
		//Testing Argon2ID
		/*byte[] salt = BinaryUtils.getSalt(32);
		byte[] fakePassword = "Password123456".getBytes();
		//System.out.println("Deriving key. This may take a moment...");
		//byte[] outputHash = PBKDF.deriveKey(fakePassword, salt); //This takes bloody forever.
		//System.out.println("Key derived.");
		//System.out.println("Key: " + BinaryUtils.bytesToHex(outputHash));
		*/
		System.out.println("Skipping Argon2 tests...");
		//Testing AES.
		System.out.println("Testing AES-CBC mode:");
		byte[] key = BinaryUtils.getSalt(32);
		byte[] iv = BinaryUtils.getSalt(16);
		byte[] msg = "Hello world!".getBytes();
		byte[] encrypted = AES.encryptCBC(key, iv, msg);
		System.out.println("Ciphertext: " + BinaryUtils.bytesToHex(iv) + BinaryUtils.bytesToHex(encrypted));
		byte[] decrypted = AES.decryptCBC(key, iv, encrypted);
		System.out.println("Decrypted ciphertext: " + new String(decrypted));
		System.out.println("Testing AES-GCM mode:");
		byte[] encryptedGCM = AES.encryptGCM(key, iv, msg);
		System.out.println("Testing decryption of valid ciphertext...");
		byte[] decryptedGCM;
		try {
			decryptedGCM = AES.decryptGCM(key, iv, encryptedGCM);
			System.out.println("Decrypted ciphertext: " + new String(decryptedGCM));
		} catch (AEADBadTagException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("Valid ciphertext got rejected!");
		}
		
		System.out.println("Testing decryption of modified ciphertext...");
		encryptedGCM[0] = (byte) (encryptedGCM[0] ^ 0x4e);
		byte[] forgedMsg;
		try {
			forgedMsg = AES.decryptGCM(key, iv, encryptedGCM);
			System.out.println("Decrypted forgery: " + new String(forgedMsg));
		} catch (NullPointerException | AEADBadTagException e) {
			System.out.println("Forged message rejected!");
		}
		System.out.println("AES tests complete.");
		
	}

}
