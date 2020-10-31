package me.DanL.ThreadedClient.Primary;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.util.Base64;
import java.util.UUID;

import me.DanL.E2EChat.CryptoUtils.AES;
import me.DanL.E2EChat.CryptoUtils.BinaryUtils;
import me.DanL.E2EChat.CryptoUtils.RSAKey;
import me.DanL.E2EChat.CryptoUtils.RSAKey.MalformedKeyFileException;
import me.DanL.PacketManager.Connection;

public class ChatNetClient {
	
	private UUID clientUid;
	
	private RSAKey clientKey;
	
	private byte[] serverAuthMasterSecret;
	
	private String srvIp = "";
	private int srvPort;
	
	/**
	 * Initialises the client that talks to the server.
	 * This method will load the key from a file, decrypt it and then contact the server to get our master secret.
	 * @param privateKeyFile - The file to load the encrypted private key from. The file is in the format KDF-salt||IV||<AES-256-CBC encrypted XML>
	 * @param loadKey - The cryptographic key to load the file from.
	 * @throws IOException - If file read went wrong
	 * @throws MalformedKeyFileException - If the XML was invalid (this almost certainly means the password was wrong).
	 */
	public ChatNetClient(File privateKeyFile, byte[] loadKey) throws IOException, MalformedKeyFileException {
		FileInputStream fis = new FileInputStream(privateKeyFile);
		byte[] iv = new byte[16];
		assert (32 == fis.skip(32)); //This is the key derivation salt, so skip it.
		fis.read(iv);
		byte[] encryptedXML = new byte[fis.available()];
		fis.read(encryptedXML);
		fis.close(); //No longer needed.
		byte[] decryptedXML;
		try {
			decryptedXML = AES.decryptCBC(loadKey, iv, encryptedXML);
		} catch (InvalidKeyException e) {
			//Key wasn't 32 bytes, so make an angry message appear in console.
			e.printStackTrace();
			return;
		}
		String xmlKey = new String(decryptedXML);
		clientKey = new RSAKey(xmlKey, false);
		
	}
	
	/**
	 * Generates an RSA key for first time use.
	 * @throws IOException 
	 */
	public ChatNetClient(File saveToFile, byte[] derivedKey, byte[] salt) throws IOException {
		clientKey = new RSAKey();
		saveKeyToFile(saveToFile, derivedKey, salt);
	}
	
	/**
	 * Saves the RSA key to file encrypted.
	 * @param where - The file to save to.
	 * @param encryptionKey - The key used to encrypt the file.
	 * @param passSalt - The salt used to derive the encryptionKey.
	 * @throws IOException - If the key was invalid, or some other file write failed.
	 */
	public void saveKeyToFile(File where, byte[] encryptionKey, byte[] passSalt) throws IOException{
		FileOutputStream fos = new FileOutputStream(where);
		fos.write(passSalt);
		byte[] encIv = BinaryUtils.getSalt(16);
		fos.write(encIv);
		byte[] decryptedXML = clientKey.savePrivateToString().getBytes();
		byte[] encryptedXML;
		try {
			encryptedXML = AES.encryptCBC(encryptionKey, encIv, decryptedXML);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			fos.close();
			throw new IOException("Invalid save key!");
		}
		fos.write(encryptedXML);
		fos.close();
	}
	
	/**
	 * Initialises the client connector. Will automatically register with the server if required.
	 * @param ip
	 * @param port
	 * @throws IOException - If some socket ops failed
	 * @throws UnknownHostException - If the server address was invalid
	 */
	public void init(String ip, int port, UUID usUid, String name) throws UnknownHostException, IOException {
		clientUid = usUid;
		//Manually create the socket so we have a persistent connection.
		srvPort = port;
		srvIp = ip;
		Socket s = new Socket(ip, port);
		Connection.send(s, "HELLO " + usUid.toString());
		String[] resp = new String(Connection.readDat(s, 65535)).split(" "); //Could be a challenge, so receive a lot of data.
		if (resp[0].contentEquals("NEW")) {
			//We need to register.
			Connection.send(s, "PERSON " + name);
			Connection.send(s, "CRYPT " + clientKey.savePublicToString());
			resp = new String(Connection.readDat(s, 65535)).split(" "); //Should be a challenge.
		}
		if (resp[0].contentEquals("CHALLENGE")) {
			byte[] c = Base64.getDecoder().decode(resp[1]);
			serverAuthMasterSecret = clientKey.decrypt(c); //Decrypts the challenge bytes.
			System.out.println("Token: " + Base64.getEncoder().encodeToString(serverAuthMasterSecret)); //Remove once done testing.
		}
	}
	
	/**
	 * @return the clientUid
	 */
	public UUID getClientUid() {
		return clientUid;
	}
	
}
