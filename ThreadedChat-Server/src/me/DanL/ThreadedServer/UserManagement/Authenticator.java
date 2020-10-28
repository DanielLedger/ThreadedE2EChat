package me.DanL.ThreadedServer.UserManagement;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.HashMap;
import java.util.UUID;

import me.DanL.E2EChat.CryptoUtils.BinaryUtils;
import me.DanL.E2EChat.CryptoUtils.RSAKey;
import me.DanL.E2EChat.CryptoUtils.RSAKey.MalformedKeyFileException;

public class Authenticator {
	
	private HashMap<UUID,byte[]> sessionSecrets = new HashMap<UUID,byte[]>();
	private HashMap<String,UUID> uidLookup = new HashMap<String,UUID>();
	
	private File storageDir;
	
	
	public Authenticator(File keyStorageDir) {
		storageDir = keyStorageDir;
		storageDir.mkdirs();
	}
	
	public Authenticator() {
		// TODO Remove when no longer needed for testing.
	}

	public synchronized boolean packetAuthed(String payload, UUID user, int packetNum, byte[] authGiven) {
		//TODO: Actually write authentication code.
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
	}
	
	/**
	 * Resets and returns a user's session key.
	 * @param who - The user we want to reset.
	 * @return - The user's new session key.
	 */
	public byte[] resetUserSessionKey(UUID who) {
		byte[] newKey = BinaryUtils.getSalt(32); //New session token.
		sessionSecrets.put(who, newKey);
		return newKey;
	}
}
