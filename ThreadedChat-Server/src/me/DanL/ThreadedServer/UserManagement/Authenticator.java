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
	
	
	
}
