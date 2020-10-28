package me.DanL.ThreadedServer.UserManagement;

import java.io.File;
import java.util.HashMap;
import java.util.UUID;

public class Authenticator {
	
	private HashMap<UUID,byte[]> sessionSecrets = new HashMap<UUID,byte[]>();
	private File storageDir;
	
	
	public Authenticator(File keyStorageDir) {
		storageDir = keyStorageDir;
	}
	
	public synchronized boolean packetAuthed(String payload, UUID user, int packetNum, byte[] authGiven) {
		//TODO: Actually write authentication code.
		return true;
	}
	
}
