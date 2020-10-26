import me.DanL.E2EChat.CryptoUtils.HMACUtils;
import me.DanL.E2EChat.CryptoUtils.HMACUtils.InvalidMACException;

public class Main {
	public static void main(String[] args) {
		tests(); //Tests the various cryptographic primitives we have.
	}
	
	private static void tests(){
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
	}
}
