
import java.io.File;
import java.io.IOException;

import me.DanL.E2EChat.CryptoUtils.HMACUtils;
import me.DanL.E2EChat.CryptoUtils.HMACUtils.InvalidMACException;
import me.DanL.E2EChat.CryptoUtils.RSAKey;
import me.DanL.E2EChat.CryptoUtils.RSAKey.MalformedKeyFileException;

public class Main {
	public static void main(String[] args) throws IOException, MalformedKeyFileException {
		tests(); //Tests the various cryptographic primitives we have.
	}
	
	private static void tests() throws IOException, MalformedKeyFileException{
		//Test HMAC hashing and verifying.
		System.out.println("Testing HMAC...");
		String data = "Hello World!";
		String key = "HMAC key";
		byte[] dataBytes = data.getBytes();
		byte[] keyBytes = key.getBytes();
		
		String hexHmac = HMACUtils.hexHmac(dataBytes, keyBytes);
		System.out.println("Got MAC of data as " + hexHmac + ".");
		System.out.println("Verifying MAC...");
		try {
			HMACUtils.verifyHexHmac(dataBytes, keyBytes, hexHmac);
			System.out.println("MAC is valid for data!");
		} catch (InvalidMACException e) {
			System.out.println("Verification failed!");
		}
		System.out.println("Verifying invalid MAC...");
		String invalidMac = HMACUtils.hexHmac(dataBytes, new byte[4]);
		try {
			HMACUtils.verifyHexHmac(dataBytes, keyBytes, invalidMac);
			System.out.println("MAC verified successfully: this is a bug.");
		} catch (InvalidMACException e) {
			System.out.println("MAC rejected.");
		}
		System.out.println("HMAC tests complete.");
		//Test RSA keypair saving, loading, and cryptography.
		System.out.println("Testing RSA...");
		RSAKey rk = new RSAKey();
		byte[] encrypted = rk.encrypt(dataBytes);
		System.out.println("Encrypted data: " + HMACUtils.bytesToHex(encrypted));
		byte[] decrypted = rk.decrypt(encrypted);
		System.out.println("Decrypted data: " + new String(decrypted));
		System.out.println("Testing saving public key: ");
		rk.savePublic(new File("test.pub"));
		System.out.println("Public key saved successfully! Saving private key: ");
		rk.savePrivate(new File("test"));
		System.out.println("Private key saved successfully!");
		System.out.println("Trying to decrypt data from earlier using saved private key:");
		RSAKey loadedKey = new RSAKey(new File("test"));
		System.out.println("Decrypted string: " + new String(loadedKey.decrypt(encrypted)));
		
	}
}
