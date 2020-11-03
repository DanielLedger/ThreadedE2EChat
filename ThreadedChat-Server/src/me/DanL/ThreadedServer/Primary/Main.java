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
		Server.setAuthProvider(new Authenticator(keyStorageDirectory,new File("users.csv")));
		Server.setMsgSaveFile(new File("msgs.csv"));
		Server.debugOutput("Listening for packets on port 4444.");
		final int packetMaxLen = Integer.MAX_VALUE; //Make absolutely 100% sure we don't miss anything.
		while (true) {
			try {
				Connection.onRecv(4444, packetMaxLen, mph);
			}
			catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

}
