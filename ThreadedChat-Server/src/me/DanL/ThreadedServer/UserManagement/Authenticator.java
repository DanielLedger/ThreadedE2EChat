package me.DanL.ThreadedServer.UserManagement;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Scanner;
import java.util.Map.Entry;
import java.util.UUID;


import me.DanL.E2EChat.CryptoUtils.BinaryUtils;
import me.DanL.E2EChat.CryptoUtils.HMACUtils;
import me.DanL.E2EChat.CryptoUtils.HMACUtils.InvalidMACException;
import me.DanL.E2EChat.CryptoUtils.RSAKey;
import me.DanL.E2EChat.CryptoUtils.RSAKey.MalformedKeyFileException;
import me.DanL.ThreadedServer.Primary.Server;

public class Authenticator {
	
	private HashMap<UUID,byte[]> sessionSecrets = new HashMap<UUID,byte[]>();
	private HashMap<UUID,Integer> userLastPacketNum = new HashMap<UUID,Integer>();
	private HashMap<String,UUID> uidLookup = new HashMap<String,UUID>();
	
	private File storageDir;
	
	private File userInfoFile;
	
	
	public Authenticator(File keyStorageDir, File userInfoLoadFrom) {
		storageDir = keyStorageDir;
		storageDir.mkdirs();
		userInfoFile = userInfoLoadFrom;
		try {
			loadUsers();
		} catch (FileNotFoundException e) {
			//Silently ignore
		}
	}
	
	/**
	 * Loads the uidLookup table from disk.
	 * @throws FileNotFoundException 
	 */
	public void loadUsers() throws FileNotFoundException {
		Scanner fileReader = new Scanner(userInfoFile);
		while (fileReader.hasNextLine()) {
			//Assuming a name,UUID pair
			String[] parts = fileReader.nextLine().trim().split(",");
			String name = parts[0];
			UUID uid = UUID.fromString(parts[1]); //Should always be valid.
			uidLookup.put(name, uid);
		}
		fileReader.close();
	}

	/**
	 * Saves the users file to disk.
	 * @throws IOException
	 */
	public void saveUsers() throws IOException {
		FileOutputStream fos = new FileOutputStream(userInfoFile);
		for (Entry<String, UUID> e: uidLookup.entrySet()) {
			String toWrite = e.getKey() + "," + e.getValue().toString() + "\n";
			fos.write(toWrite.getBytes());
		}
		fos.close();
	}
	
	public synchronized boolean packetAuthed(String payload, UUID user, int packetNum, byte[] authGiven) {
		int lastPacket = userLastPacketNum.getOrDefault(user, 0);
		if (packetNum <= lastPacket) {
			Server.debugOutput("Packet number is lower than or equal to a previous packet number, assuming replay attack and rejecting.");
			return false;
		}
		byte[] toSign = new byte[36]; //4 bytes for the packet number + 32 for the hash.
		ByteBuffer bb = ByteBuffer.allocate(4);
		bb.putInt(packetNum);
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
		if (!sessionSecrets.containsKey(user)) {
			Server.debugOutput("User hasn't initialised a session, rejecting.");
			return false; //Null key will fail and a hardcoded default key would allow auth bypass.
		}
		try {
			HMACUtils.verifyHmac(toSign, sessionSecrets.get(user), authGiven);
		} catch (InvalidMACException e) {
			Server.debugOutput("Packet MAC invalid, rejecting.");
			return false;
		}
		userLastPacketNum.put(user, packetNum);
		return true;
	}
	
	/**
	 * Get a user's saved public key.
	 * @param who - The UUID of the user we're getting the key for.
	 * @return - The user's public key, or null if they do not have one.
	 */
	public RSAKey getUserPubKey(UUID who) {
		String xmlFileName = who.toString() + "-pub.xmlkey";
		File kFile = new File(storageDir.getPath() + File.separator + xmlFileName);
		try {
			RSAKey userKey = new RSAKey(kFile);
			return userKey;
		} catch (FileNotFoundException e) {
			// No key on file.
			return null;
		} catch (MalformedKeyFileException e) {
			// The key file we have for them is malformed, remove it and return null.
			kFile.delete();
			return null;
		}
	}
	
	/**
	 * Saves the given RSAKey for the record of this user.
	 * @param who - The user who's key we're saving.
	 * @param key - Their key.
	 * @throws IOException - If something went wrong.
	 */
	public void saveUserPubKey(UUID who, RSAKey key) throws IOException {
		String xmlFileName = who.toString() + "-pub.xmlkey";
		File kFile = new File(storageDir.getPath() + File.separator + xmlFileName);
		key.savePublic(kFile);
	}
	
	/**
	 * Adds a user to our database of user.
	 * @param uid - The user's UID. Should never change.
	 * @param pubKey - The user's public key. Once set, cannot be changed.
	 * @param name - The user's name. I may add a way to change this.
	 * @throws IOException - If saving the user's public key fails.
	 */
	public void addUser(UUID uid, RSAKey pubKey, String name) throws IOException {
		uidLookup.put(name, uid);
		saveUserPubKey(uid, pubKey);
		saveUsers();
	}
	
	/**
	 * Resets and returns a user's session key.
	 * @param who - The user we want to reset.
	 * @return - The user's new session key.
	 */
	public byte[] resetUserSessionKey(UUID who) {
		byte[] newKey = BinaryUtils.getSalt(32); //New session token.
		sessionSecrets.put(who, newKey);
		userLastPacketNum.put(who, 0); //Resets the user's packet counter.
		return newKey;
	}
	
	/**
	 * Look up a UUID and return a name.
	 * @param who - The UUID to look up.
	 * @return The user's UUID, or null if they couldn't be found.
	 */
	public String getName(UUID who) {
		for (Entry<String, UUID> e: uidLookup.entrySet()) {
			if (e.getValue().equals(who)) {
				return e.getKey();
			}
		}
		return null;
	}
	
	public UUID getUid(String who) {
		return uidLookup.get(who);
	}
	
	
}
