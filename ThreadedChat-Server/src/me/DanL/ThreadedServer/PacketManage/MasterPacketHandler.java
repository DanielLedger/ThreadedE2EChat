package me.DanL.ThreadedServer.PacketManage;

import java.io.IOException;
import java.net.Socket;

import me.DanL.PacketManager.Connection;
import me.DanL.PacketManager.DataReceiver;

public class MasterPacketHandler implements DataReceiver {

	@Override
	public void getData(Socket source, String data) {
		System.out.println(data);
		try {
			Connection.send(source, "Hi!");
		} catch (IOException e) {
			//Well that failed...
			e.printStackTrace();
		}
		
	}

}
