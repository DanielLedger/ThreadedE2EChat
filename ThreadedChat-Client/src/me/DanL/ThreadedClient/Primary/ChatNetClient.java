package me.DanL.ThreadedClient.Primary;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.UUID;

import me.DanL.E2EChat.CryptoUtils.AES;
import me.DanL.E2EChat.CryptoUtils.BinaryUtils;
import me.DanL.E2EChat.CryptoUtils.HMACUtils;
import me.DanL.E2EChat.CryptoUtils.RSAKey;
import me.DanL.E2EChat.CryptoUtils.RSAKey.MalformedKeyFileException;
import me.DanL.PacketManager.Connection;

public class ChatNetClient {
	
	private UUID clientUid;
	
	private RSAKey clientKey;
	
	private byte[] serverAuthMasterSecret;
	
	private String srvIp = "";
	private int srvPort;
	
	private int packetNumber = 0;
	
	/**
	 * Not just literal messages, also control messages.
	 */
	private volatile ArrayList<String> messages = new ArrayList<String>(); //Volatile because the program requires multiple threads.
	
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
		packetNumber = 1; //Packet number is zero by default, so a start number of zero will be rejected.
		s.close();
	}
	
	/**
	 * Signs a packet.
	 * @param payload - The payload to sign.
	 * @return - The base64 encoded signature of the packet.
	 */
	private String signPayload(String payload) {
		byte[] toSign = new byte[36]; //4 bytes for the packet number + 32 for the hash.
		ByteBuffer bb = ByteBuffer.allocate(4);
		bb.putInt(packetNumber);
		byte[] packetNumAsBytes = bb.array();
		for (byte i = 0;i<4;i++) {
			toSign[i] = packetNumAsBytes[i];
		}
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] sha = md.digest(payload.getBytes());
			for (byte i = 0;i<32;i++) {
				toSign[i+4] = sha[i];
			}
		} catch (NoSuchAlgorithmException e) {
			//?????
			e.printStackTrace();
		}
		packetNumber++; //Very important, otherwise our packets will get rejected repeatedly.
		return Base64.getEncoder().encodeToString(HMACUtils.hmac(toSign, serverAuthMasterSecret));
	}
	
	/**
	 * Takes the data we've been given and crafts it into a valid SEND packet.
	 * @param rawData - The raw, base64 encoded data of the packet.
	 * @param sendto - Who we send the data to.
	 * @return
	 */
	private String createPacket(String rawData, UUID sendTo) {
		//Format is SEND <data> <their UUID> <packet number> <token> <our UUID>
		return "SEND " + rawData + " " + sendTo.toString() + " " + packetNumber + " " + signPayload(rawData + " " + sendTo.toString()) + " " + clientUid.toString(); 
	}
	
	/**
	 * Send a message to the client we want to communicate with.
	 * @param data - The data to send.
	 * @param to - Whom we are sending that data to.
	 * @throws IOException - If something fails when sending.
	 */
	public synchronized void sendClientMessage(byte[] data, UUID to) throws IOException { //Synchronized because trying to send two messages at once may lead to them both having invalid signatures.
		String encoded = Base64.getEncoder().encodeToString(data);
		String packet = createPacket(encoded, to);
		try {
			Connection.send(srvIp, srvPort, packet);
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
	}
	
	/**
	 * @return the clientUid
	 */
	public UUID getClientUid() {
		return clientUid;
	}
	
	/**
	 * Download a user's RSA key from the server.
	 * @param who - The user who's key we're downloading.
	 * @return - The user's RSA key.
	 * @throws IOException - The connection to the server fails.
	 */
	public RSAKey getUserKey(UUID who) throws IOException {
		String payload = who.toString();
		String packet = "KEY " + payload + " " + packetNumber + " " + signPayload(payload) + " " + clientUid.toString();
		Socket s = new Socket(srvIp, srvPort);
		Connection.send(s, packet);
		byte[] dat = Connection.readDat(s, 65535);
		String[] respParts = new String(dat).split(" ");
		if (respParts[0].contentEquals("PKEY")) {
			try {
				return new RSAKey(respParts[1], false);
			} catch (MalformedKeyFileException e) {
				return null;
			}
		}
		else {
			return null;
		}
		
		
	}

	public RSAKey getClientKey() {
		return clientKey;
	}
	
	/**
	 * Contact the server and request any messages we haven't yet seen. Stores them into the messages buffer.
	 * @throws IOException 
	 */
	public void getUnreadMessages() throws IOException {
		String packet = "MESSAGES " + packetNumber + " " + signPayload("") + " " + clientUid.toString();
		Socket s = new Socket(srvIp, srvPort);
		Connection.send(s, packet);
		String len = new String(Connection.readDat(s, 1024)); //This message says how long the second message is.
		int bufferLen = 0;
		try {
			bufferLen = Integer.parseInt(len.replace("\n", "").split(" ")[1]);
		}
		catch (NumberFormatException | ArrayIndexOutOfBoundsException e) {
			return; //Invalid
		}
		if (bufferLen == 0) {
			//No new messages
			return;
		}
		String messageList = new String(Connection.readDat(s, bufferLen));
		//The messages are essentially semicolon separated lists of messages, so we can just split and add.
		String[] msgs = messageList.replace("MSG", "").split(";");
		for (String msg: msgs) {
			messages.add(msg);
		}
	}
	
	public String getUsername(UUID person) {
		return "Bob"; //Not implemented yet: fairly quick implementation though.
	}
	
	/**
	 * Returns and wipes the unread messages buffer.
	 * @return
	 */
	public ArrayList<String> getAndClearMessages(){
		@SuppressWarnings("unchecked")
		ArrayList<String> bufferRet = (ArrayList<String>) messages.clone();
		messages.clear();
		return bufferRet;
	}
	
	public void retLoop() {
		while (true) {
			//Forever checking new messages and downloading if found.
			try {
				Thread.sleep(1000);
				getUnreadMessages();
			} catch (InterruptedException e) {
				//???
				e.printStackTrace();
			} //Checking every second.
			catch (IOException e) {
				//Probably bad.
				e.printStackTrace();
			}
		}
	}
	
}
