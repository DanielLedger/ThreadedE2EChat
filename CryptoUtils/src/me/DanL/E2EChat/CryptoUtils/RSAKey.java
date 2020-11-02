package me.DanL.E2EChat.CryptoUtils;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
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
	 * Loads an  RSA key from an XML file.
	 * @param loadFrom - The file to load the key from. Key must be in XML format.
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
		loadKeysFromXML(rawData, false);
		
	}
	
	/**
	 * Loads a key from a string
	 * @param xmlData - The XML to load the key from
	 * @param unsafe - Allow the key to be loaded, even if it doesn't have valid public key info?
	 * @throws MalformedKeyFileException 
	 */
	public RSAKey(String xmlData, boolean unsafe) throws MalformedKeyFileException {
		loadKeysFromXML(xmlData, unsafe);
	}
	
	private String getDataBetweenTags(String dataSet, String tagName) {
		String[] splitRes = dataSet.split("<\\/?" + tagName + ">");
		if (splitRes.length <= 1) {
			return "";
		}
		else {
			return splitRes[1];
		}
	}
	
	private void loadKeysFromXML(String xml, boolean unsafe) throws MalformedKeyFileException {
		BigInteger modulus = null;
		BigInteger publicExp = null;
		BigInteger privExp = null;
		String encodedN = getDataBetweenTags(xml, "Modulus");
		String encodedE = getDataBetweenTags(xml, "Exponent");
		String encodedD = getDataBetweenTags(xml, "D");
		if (!encodedN.contentEquals("")) {
			modulus = new BigInteger(Base64.getDecoder().decode(encodedN));
		}
		if (!encodedE.contentEquals("")) {
			publicExp = new BigInteger(Base64.getDecoder().decode(encodedE));
		}
		if (!encodedD.contentEquals("")) {
			privExp = new BigInteger(Base64.getDecoder().decode(encodedD));
		}
		if (!unsafe && (modulus == null || publicExp == null)) {
			//Invalid key (since we'd expect both of these)
			throw new MalformedKeyFileException();
		}
		RSAPublicKeySpec pubKeySpec = null;
		RSAPrivateKeySpec privKeySpec = null;
		if (privExp != null) {
			privKeySpec = new RSAPrivateKeySpec(modulus, privExp);
		}
		if (publicExp != null) {
			pubKeySpec = new RSAPublicKeySpec(modulus, publicExp);
		}
		try {
			KeyFactory kf = KeyFactory.getInstance("RSA");
			if (privKeySpec != null) {
				privKey = (RSAPrivateKey) kf.generatePrivate(privKeySpec);
			}
			if (pubKeySpec != null) {
				pubKey = (RSAPublicKey) kf.generatePublic(pubKeySpec);
			}
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			//Uh oh...
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
		}
		try {
			privKey.destroy();
		} catch (DestroyFailedException e) {
			//This is bad but not the end of the world.
			e.printStackTrace();
		} //Securely delete the contents of the key from memory.
		privKey = null;
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
	 * Permanently destroys the key. All future calls to most functions in this key
	 * will probably throw a NullPointerException. This may be quite slow since it
	 * generates a second keypair to overwrite the first in memory.
	 */
	public void burnKey() {
		//Correctly destroy the private key.
		if (privKey != null) {
			try {
				privKey.destroy();
			} catch (DestroyFailedException e) {
				e.printStackTrace();
			}
			privKey = null;
		}
		//Now, overwrite where the keys used to be in memory. Not sure if this will work, but worth a shot.
		KeyPairGenerator gen;
		try {
			gen = KeyPairGenerator.getInstance("RSA");
			gen.initialize(1024); //This doesn't need to be secure, it just needs to overwrite the key pairs in memory.
			KeyPair kp = gen.generateKeyPair();
			privKey = (RSAPrivateKey) kp.getPrivate();
			pubKey = (RSAPublicKey) kp.getPublic();
			privKey = null;
			pubKey = null;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
	}
	
	/**
	 * Inverts this private key (e <=> d)
	 * @return The inverted key. Note that although a public key can be inverted, the results will be weird and unstable.
	 */
	public RSAKey invertKey() {
		String xmlRep = savePrivateToString();
		xmlRep = xmlRep.replace("<Exponent>", "<K>").replace("</Exponent>", "</K>")
				.replace("<D>", "<Exponent>").replace("</D>", "</Exponent>")
				.replace("<K>", "<D>").replace("</K>", "<K>");
		try {
			return new RSAKey(xmlRep, true);
		} catch (MalformedKeyFileException e) {
			//Seems it was doing checks I wasn't aware of.
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
	 * Saves the private key to a string, instead of to a file. Useful for key encryption.
	 * @return
	 */
	public String savePrivateToString() {
		BigInteger modulus = pubKey.getModulus();
		BigInteger publicExp = pubKey.getPublicExponent();
		BigInteger privExp = privKey.getPrivateExponent();
		String encodedModulus = Base64.getEncoder().encodeToString(modulus.toByteArray());
		String encodedPublicExp = Base64.getEncoder().encodeToString(publicExp.toByteArray());
		String encodedPrivExp = Base64.getEncoder().encodeToString(privExp.toByteArray());
		/*Since we don't care about compatibility too much, we can do quite a pathetic imitation
		of the actual key save spec. Just so long as we can understand ourselves.*/
		return "<Modulus>" + encodedModulus + "</Modulus>\n<Exponent>" + encodedPublicExp + "</Exponent>\n<D>" + encodedPrivExp + "</D>";
	}
	
	/**
	 * Another utility method for saving a public key to a string.
	 * @return
	 */
	public String savePublicToString() {
		BigInteger modulus = pubKey.getModulus();
		BigInteger publicExp = pubKey.getPublicExponent();
		String encodedModulus = Base64.getEncoder().encodeToString(modulus.toByteArray());
		String encodedPublicExp = Base64.getEncoder().encodeToString(publicExp.toByteArray());
		/*Since we don't care about comaptibility too much, we can do quite a pathetic imitation
		of the actual key save spec. Just so long as we can understand ourselves.*/
		return "<Modulus>" + encodedModulus + "</Modulus>\n<Exponent>" + encodedPublicExp + "</Exponent>";
	}
	
	/**
	 * Saves the public key to a file.
	 * @param saveTo
	 * @throws IOException 
	 */
	public void savePublic(File saveTo) throws IOException {
		String rawData = savePublicToString();
		FileOutputStream fos = new FileOutputStream(saveTo);
		fos.write(rawData.getBytes());
		fos.close();
	}
	
	/**
	 * Saves the private key to a file. Note that this will not encrypt the private key (this should be done in 99% of cases).
	 * @param saveTo - The file to write to.
	 * @throws IOException
	 */
	public void savePrivate(File saveTo) throws IOException {
		String rawData = savePrivateToString();
		FileOutputStream fos = new FileOutputStream(saveTo);
		fos.write(rawData.getBytes());
		fos.close();
	}
	
	/**
	 * Gets the SHA256 hash of the public modulus of this key.
	 * @return
	 */
	public byte[] getKeyHash() {
		MessageDigest md;
		try {
			md = MessageDigest.getInstance("SHA-256");
			return md.digest(pubKey.getModulus().toByteArray());
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null; //??
		
	}
}
