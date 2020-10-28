package me.DanL.ThreadedServer.Primary;

import java.io.File;
import java.io.IOException;

import me.DanL.PacketManager.Connection;
import me.DanL.ThreadedServer.PacketManage.MasterPacketHandler;
import me.DanL.ThreadedServer.UserManagement.Authenticator;

public class Main {

	public static void main(String[] args) throws IOException {
		MasterPacketHandler mph = new MasterPacketHandler();
		File keyStorageDirectory = new File("crypt/keys");
		Server.setAuthProvider(new Authenticator(keyStorageDirectory));
		while (true) {
			Connection.onRecv(4444, 65535, mph);
		}
	}

}
