package me.DanL.ThreadedServer.Primary;

import java.io.IOException;

import me.DanL.PacketManager.Connection;
import me.DanL.ThreadedServer.PacketManage.MasterPacketHandler;

public class Main {

	public static void main(String[] args) throws IOException {
		MasterPacketHandler mph = new MasterPacketHandler();
		while (true) {
			Connection.onRecv(4444, 2048, mph);
		}
	}

}
