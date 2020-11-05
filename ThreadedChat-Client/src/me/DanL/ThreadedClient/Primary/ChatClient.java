package me.DanL.ThreadedClient.Primary;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;
import java.util.HashMap;
import java.util.List;
import java.util.Scanner;
import java.util.Set;
import java.util.UUID;

import me.DanL.E2EChat.CryptoUtils.AES;
import me.DanL.E2EChat.CryptoUtils.BinaryUtils;
import me.DanL.E2EChat.CryptoUtils.HMACUtils;
import me.DanL.E2EChat.CryptoUtils.PBKDF;
import me.DanL.E2EChat.CryptoUtils.RSAKey;
import me.DanL.E2EChat.CryptoUtils.RSAKey.InvalidSignatureException;


/**
 * Handles letting the user chat to others.
 * @author daniel
 *
 */
public class ChatClient {
	HashMap<UUID,byte[]> secretStore = new HashMap<UUID,byte[]>();
	HashMap<UUID,Integer> msgCtr = new HashMap<UUID,Integer>(); //Currently not used while messages are ephemeral.
	HashMap<UUID,String> nameLookup = new HashMap<UUID, String>();
	HashMap<UUID,byte[]> pubkeyHash = new HashMap<UUID, byte[]>();
	HashMap<UUID, byte[]> hmacSalts = new HashMap<UUID, byte[]>();
	
	HashMap<UUID,ArrayList<Message>> unreadToMe = new HashMap<UUID,ArrayList<Message>>();
	
	byte[] mKey;
	
	File dataSaveFile;
	
	ChatNetClient networkHandle;
	
	public ChatClient(byte[] masterKey, File loadFrom, ChatNetClient networkOp) throws FileNotFoundException {
		dataSaveFile = loadFrom;
		mKey = masterKey;
		networkHandle = networkOp;
		if (!loadFrom.exists()) {
			return; //No data file exists.
		}
		Scanner sc = new Scanner(loadFrom);
		while (sc.hasNextLine()) {
			try {
				String csvLine = sc.nextLine();
				String[] dataParts = csvLine.split(",");
				assert (dataParts.length == 5);
				//We know it's the right length, so grab the required data from the line.
				UUID rowId = UUID.fromString(dataParts[0]);
				String name = dataParts[1];
				String keyHash = dataParts[2]; //Hash in base64.
				byte[] hmacSalt = Base64.getDecoder().decode(dataParts[3]);
				byte[] encryptedSecret = Base64.getDecoder().decode(dataParts[4]);
				byte[] key = HMACUtils.hmac(masterKey, hmacSalt); //Calculate as in spec.
				secretStore.put(rowId, AES.decryptCBC(key, hmacSalt, encryptedSecret));
				nameLookup.put(rowId, name);
				pubkeyHash.put(rowId, Base64.getDecoder().decode(keyHash));
				hmacSalts.put(rowId, hmacSalt);
			} 
			catch (InvalidKeyException e) {
				//Skip row because the key was encrypted wrongly.
				e.printStackTrace();
			}
		}
		sc.close();
	}
	
	/**
	 * Saves the data we have to a file.
	 * @param masterKey - The key to use for encrypting master secrets
	 * @param saveTo - The file to save to.
	 * @throws IOException - If something fails when reading or writing the file.
	 */
	public void saveData() throws IOException {
		FileOutputStream fos = new FileOutputStream(dataSaveFile);
		for (UUID user: nameLookup.keySet()) {
			String[] dataRow = new String[5];
			dataRow[0] = user.toString();
			dataRow[1] = nameLookup.get(user);
			dataRow[2] = Base64.getEncoder().encodeToString(pubkeyHash.get(user));
			dataRow[3] = Base64.getEncoder().encodeToString(hmacSalts.get(user));
			byte[] encKey = HMACUtils.hmac(mKey, hmacSalts.get(user));
			byte[] encryptedSecret = null;
			try {
				encryptedSecret = AES.encryptCBC(encKey, hmacSalts.get(user), secretStore.get(user));
			} catch (InvalidKeyException e) {
				// This should never happen?????
				e.printStackTrace();
			}
			dataRow[4] = Base64.getEncoder().encodeToString(encryptedSecret);
			//Now, convert this row into a byte array (because writing files needs bytes)
			byte[] row = String.join(",", dataRow).getBytes();
			fos.write(row);
		}
		fos.close();
	}
	
	/**
	 * Add a user to chat. Since we generate the secret and send it to them, they can also immediately have messages sent to them.
	 * @param who
	 * @param skipIfAdded - Skips the whole process if we have a session on record with this person already.
	 * @throws IOException - If communication with the server fails.
	 */
	public void addUser(UUID who, boolean skipIfAdded) throws IOException {
		if (hasSession(who) && skipIfAdded) {
			return; //Do nothing.
		}
		byte[] masterSecret = BinaryUtils.getSalt(32); //The master secret for use when talking to someone.
		//Add now, since we overwrite this later
		secretStore.put(who, masterSecret);
		byte[] hmacSalt = BinaryUtils.getSalt(16); //Used as key-deriv salt and IV for secret storage.
		//Now, download their public key from the server.
		RSAKey userKey = networkHandle.getUserKey(who);
		masterSecret = userKey.encrypt(masterSecret); //Deliberately overwrite masterSecret in memory.
		byte[] proofOfId = networkHandle.getClientKey().signData(networkHandle.getClientUid().toString().getBytes());
		Encoder b64enc = Base64.getEncoder();
		String initPacket = "INIT " + b64enc.encodeToString(proofOfId) + " " + networkHandle.getClientUid().toString() + " " + b64enc.encodeToString(masterSecret);
		//Send the user the INIT packet
		networkHandle.sendClientMessage(initPacket.getBytes(), who);
		//Now finally, add the user to our data storage and save our data storage.
		pubkeyHash.put(who, userKey.getKeyHash());
		nameLookup.put(who, getUsername(who));
		hmacSalts.put(who, hmacSalt);
		saveData();
	}
	
	/**
	 * Receives a message handshake from another user.
	 * Verifies that everything is in order and then adds their master secret to our list.
	 * @param trigger
	 * @throws IOException 
	 */
	private void recvHandshake(String trigger) throws IOException {
		String[] parts = trigger.split(" ");
		assert (parts.length == 4); //Packet in 4 parts: Type, Encrypted user ID, Cleartext user ID, Encrypted master secret.
		assert (parts[0].contentEquals("INIT"));
		UUID sender = UUID.fromString(parts[2]);
		Decoder b64dec = Base64.getDecoder();
		byte[] encUid = b64dec.decode(parts[1]);
		byte[] encSecret = b64dec.decode(parts[3]);
		RSAKey senderKey = networkHandle.getUserKey(sender);
		try {
			senderKey.verifyData(sender.toString().getBytes(), encUid);
		} catch (InvalidSignatureException e) {
			e.printStackTrace();
			return;
		}
		secretStore.put(sender, networkHandle.getClientKey().decrypt(encSecret)); //Decrypts the master secret and saves it.
		//Now the cryptography is out of the way, do the other stuff.
		nameLookup.put(sender, getUsername(sender));
		byte[] hmacSalt = BinaryUtils.getSalt(16);
		hmacSalts.put(sender, hmacSalt);
		pubkeyHash.put(sender, senderKey.getKeyHash());
	}
	
	public void handleUnreads() {
		for (String s: networkHandle.getAndClearMessages()) {
			String rawData = new String(Base64.getDecoder().decode(s.trim()));
			String[] packet = rawData.split(" ");
			if (packet[0].contentEquals("INIT")) {
				try {
					recvHandshake(rawData);
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			else if (packet[0].contentEquals("MSG")) {
				Message msgForUser = new Message(packet[1]);
				UUID from = UUID.fromString(packet[2]);
				ArrayList<Message> msgs = unreadToMe.get(from);
				msgs.add(msgForUser);
				unreadToMe.put(from, msgs);
			}
		}
		try {
			saveData();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Send a message to a user.
	 * @param content - The text of the message
	 * @param to - The message to send.
	 * @throws IOException - Server communication failed.
	 */
	public void sendMsg(String content, UUID to) throws IOException {
		int currentUserCtr = msgCtr.getOrDefault(to, 0);
		Message m = new Message(content, currentUserCtr, secretStore.get(to));
		//Send the message
		networkHandle.sendMessage(m, to);
		//Now, increment the counter that we store, so we never reuse a key.
		currentUserCtr++;
		msgCtr.put(to, currentUserCtr);
	}
	
	/**
	 * Checks to see if we have a session established with another user.
	 * @param other - The user to check.
	 * @return true if we have a session on record, false if we don't
	 */
	public boolean hasSession(UUID other) {
		return secretStore.containsKey(other);
	}
	
	public String getUsername(UUID who) {
		if (nameLookup.containsKey(who)) {
			return nameLookup.get(who);
		}
		else {
			String name = networkHandle.getUsername(who);
			if (!(name.contentEquals("null") || name.contentEquals("error."))){
				//Name is someone's actual name, so cache.
				nameLookup.put(who, name);
			}
			return name;
		}
	}
	
	/**
	 * Returns everyone this person is talking to.
	 * @return - Everyone we have a session with.
	 */
	public Set<UUID> getUuids(){
		return secretStore.keySet();
	}
	
	/**
	 * Gets the list of messages that we haven't yet read.
	 * @param who - The user to view.
	 * @return - A list of messages.
	 */
	public List<Message> getUnreadFrom(UUID who){
		return unreadToMe.getOrDefault(who, new ArrayList<Message>());
	}
	
	/**
	 * Calculates a 32 byte key digest. Takes a bloody long time.
	 * @param other - The UUID of the other person we're including in this digest.
	 * @param code - The passcode we mix into the digest.
	 * @return - The 32 byte digest.
	 */
	public byte[] getKeySummary(UUID other, String code) {
		byte[] hMe = networkHandle.getClientKey().getKeyHash();
		byte[] hOther = pubkeyHash.get(other);
		byte[] k;
		if (aSmallerB(hMe, hOther)) {
			k = PBKDF.deriveKey(hMe, hOther);
		}
		else {
			k = PBKDF.deriveKey(hOther, hMe);
		}
		return PBKDF.deriveKey(code.getBytes(), k);
	}
	
	/**
	 * Tests if byte stream a is smaller numerically than byte stream b.
	 * @param a - A
	 * @param b - B
	 * @return - If A < B numerically.
	 */
	private boolean aSmallerB(byte[] a, byte[] b) {
		if (a.length != b.length) {
			return a.length < b.length;
		}
		for (int i = 0;i<a.length;i++) {
			if (a[i] < b[i]) {
				return true;
			}
			else if (a[i] > b[i]){
				return false;
			}
		}
		return false;
	}
	
}
