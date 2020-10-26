package me.DanL.E2EChat.CryptoUtils;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.DestroyFailedException;

/**
 * A high-level interface for an RSA key.
 * @author daniel
 *
 */
public class RSAKey {
	
	private RSAPrivateKey privKey = null;
	private RSAPublicKey pubKey = null;
	
	public class MalformedKeyFileException extends Throwable{

		/**
		 * 
		 */
		private static final long serialVersionUID = -1774448706612323002L;
		
	}
	
	/**
	 * Loads an encoded RSA key from a file.
	 * @param loadFrom - The file to load the key from. Key must be in PEM format.
	 * @throws FileNotFoundException - If they key file couldn't be loaded.
	 * @throws MalformedKeyFileException - If the file provided is in an incorrect format.
	 */
	public RSAKey(File loadFrom) throws FileNotFoundException, MalformedKeyFileException {
		Scanner fileReader = new Scanner(loadFrom);
		StringBuilder sb = new StringBuilder();
		while (fileReader.hasNextLine()) {
			sb.append(fileReader.nextLine());
		}
		fileReader.close();
		String rawData = sb.toString();
		if (rawData.startsWith("-----BEGIN PUBLIC KEY-----")) {
			loadPublicKey(rawData);
		}
		else if (rawData.startsWith("-----BEGIN PRIVATE KEY-----")){
			loadPrivateKey(rawData);
		}
		else {
			throw new MalformedKeyFileException();
		}
		
	}
	
	/**
	 * Loads a key from an array of bytes.
	 * @param keyBytes - Bytes of the encoded key.
	 * @param privateKey - If true, this is a private key, If false, it's a public key.
	 */
	public RSAKey(byte[] keyBytes, boolean privateKey) {
		if (privateKey) {
			loadPrivateKeyBytes(keyBytes);
		}
		else {
			loadPublicKeyBytes(keyBytes);
		}
	}
	
	/**
	 * Takes the PEM format key and loads it into a public key, that cannot perform decryption operations.
	 * @param pemBase64
	 * 
	 */
	private void loadPublicKey(String pemBase64) {
		String rawBase64 = pemBase64.replace("-----BEGIN PUBLIC KEY-----", "")
				.replace("-----END PUBLIC KEY-----", "")
				.replace(System.lineSeparator(), "");
		byte[] rawBytes = Base64.getDecoder().decode(rawBase64);
		loadPublicKeyBytes(rawBytes);
	}
	
	private void loadPublicKeyBytes(byte[] pKey) {
		//Here's the stupid bit, because the javax.crypto package is a mess that still supports DES for some unknown reason.
		try {
			KeyFactory kf = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec x509PKSpec = new X509EncodedKeySpec(pKey);
			pubKey = (RSAPublicKey) kf.generatePublic(x509PKSpec); //Actually sets the public key for this object.
		} catch (NoSuchAlgorithmException e) {
			//????
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			//Also should never happen
			e.printStackTrace();
		}
	}
	
	/**
	 * Takes the PEM format key and loads it into a private key, that can perform decryption operations.
	 * @param pemBase64
	 */
	private void loadPrivateKey(String pemBase64) {
		String rawBase64 = pemBase64.replace("-----BEGIN PRIVATE KEY-----", "")
				.replace("-----END PRIVATE KEY-----", "")
				.replace(System.lineSeparator(), "");
		byte[] rawBytes = Base64.getDecoder().decode(rawBase64);
		loadPrivateKeyBytes(rawBytes);
	}
	
	private void loadPrivateKeyBytes(byte[] privateKey) {
		//Here's the stupid bit (again), because the javax.crypto package is a mess that still supports DES for some unknown reason.
		try {
			KeyFactory kf = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec x509PKSpec = new X509EncodedKeySpec(privateKey);
			privKey = (RSAPrivateKey) kf.generatePrivate(x509PKSpec); //Actually sets the private key for this object.
			RSAPublicKeySpec pkGenerator = new RSAPublicKeySpec(privKey.getModulus(), BigInteger.valueOf(65537)); //Now add the public key.
			pubKey = (RSAPublicKey) kf.generatePublic(pkGenerator);
		} catch (NoSuchAlgorithmException e) {
			//????
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			//Also should never happen
			e.printStackTrace();
		}
	}
	
	
	/**
	 * Generate a new RSA keypair
	 * @param bitlen - How many bits should the key be. Use 2048 or 4096 unless you have a good reason not to.
	 */
	public RSAKey(int bitlen) {
		try {
			KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
			gen.initialize(bitlen);
			KeyPair kp = gen.generateKeyPair();
			privKey = (RSAPrivateKey) kp.getPrivate();
			pubKey = (RSAPublicKey) kp.getPublic();
		} catch (NoSuchAlgorithmException e) {
			//Serious error.
			e.printStackTrace();
		}
	}
	
	/**
	 * Generate a new RSA keypair, using a reasonably sized key. This size may change at any time, so don't depend on it being constant.
	 */
	public RSAKey() {
		this(2048);
	}
	
	/**
	 * Check if this key is a public key (i.e. can't decrypt)
	 * @return
	 */
	public boolean isPublic() {
		return privKey == null;
	}
	
	/**
	 * Takes this private key and removes all info relating to the private key element, rendering it as though it was a public key loaded from file.
	 */
	public void stripToPublic() {
		if (isPublic()) {
			return;
		}
		KeyFactory kf = null;
		try {
			kf = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			//Uh oh...
		}
		if (pubKey == null) {
			RSAPublicKeySpec pkGenerator = new RSAPublicKeySpec(privKey.getModulus(), BigInteger.valueOf(65537));
			try {
				pubKey = (RSAPublicKey) kf.generatePublic(pkGenerator);
			} catch (InvalidKeySpecException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			try {
				privKey.destroy();
			} catch (DestroyFailedException e) {
				//This is bad but not the end of the world.
				e.printStackTrace();
			} //Securely delete the contents of the key from memory.
			privKey = null;
		}
	}
	
	/**
	 * Securely pads and encrypts a message msg.
	 * Since RSA is deterministic, firstly we pad with OAEP-MGF1-SHA256 <- This step is important.
	 * @param msg - The message to encrypt.
	 * @return - msg, padded securely and encrypted.
	 */
	public byte[] encrypt(byte[] msg) {
		final String algName = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"; //Ew
		try {
			Cipher cipherEnc = Cipher.getInstance(algName);
			cipherEnc.init(Cipher.ENCRYPT_MODE, pubKey);
			return cipherEnc.doFinal(msg);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			//These are all a problem.
			e.printStackTrace();
			return null;
		}
		
	}
	
	/**
	 * Decrypts and unpads the message we have been sent.
	 * @param msg - The encrypted message
	 * @return - The decrypted bytes, or null if something went wrong.
	 */
	public byte[] decrypt(byte[] msg) {
		if (isPublic()) {
			return null;
		}
		final String algName = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"; //Ew
		try {
			Cipher cipherDec = Cipher.getInstance(algName);
			cipherDec.init(Cipher.DECRYPT_MODE, privKey);
			return cipherDec.doFinal(msg);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			//These are all a problem.
			e.printStackTrace();
			return null;
		}
		
	}
	
	/**
	 * Saves the public key to a file.
	 * @param saveTo
	 * @throws IOException 
	 */
	public void savePublic(File saveTo) throws IOException {
		byte[] encKey = pubKey.getEncoded();
		String base64 = Base64.getEncoder().encodeToString(encKey);
		FileWriter fow = new FileWriter(saveTo);
		fow.write("-----BEGIN PUBLIC KEY-----" + System.lineSeparator());
		fow.write(base64 + System.lineSeparator());
		fow.write("-----END PUBLIC KEY-----" + System.lineSeparator());
		fow.close();
	}
	
	/**
	 * Saves the private key to a file. Note that this will not encrypt the private key (this should be done).
	 * @param saveTo - The file to write to.
	 * @throws IOException
	 */
	public void savePrivate(File saveTo) throws IOException {
		byte[] encKey = privKey.getEncoded();
		String base64 = Base64.getEncoder().encodeToString(encKey);
		FileWriter fow = new FileWriter(saveTo);
		fow.write("-----BEGIN PRIVATE KEY-----" + System.lineSeparator());
		fow.write(base64 + System.lineSeparator());
		fow.write("-----END PRIVATE KEY-----" + System.lineSeparator());
		fow.close();
	}
}
