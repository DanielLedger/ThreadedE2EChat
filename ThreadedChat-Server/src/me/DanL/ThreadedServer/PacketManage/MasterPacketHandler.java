package me.DanL.ThreadedServer.PacketManage;

import java.io.IOException;
import java.net.Socket;
import java.util.Base64;
import java.util.UUID;

import me.DanL.E2EChat.CryptoUtils.RSAKey;
import me.DanL.E2EChat.CryptoUtils.RSAKey.MalformedKeyFileException;
import me.DanL.PacketManager.Connection;
import me.DanL.PacketManager.DataReceiver;
import me.DanL.ThreadedServer.PacketManage.PacketParser.PacketType;
import me.DanL.ThreadedServer.Primary.Server;

public class MasterPacketHandler implements DataReceiver {

	@Override
	public void getData(Socket source, String data) {
		System.out.println(data);
		PacketParser parsedPacket = new PacketParser(data);
		if (!parsedPacket.isAuthenticated()) { //Authenticated packets are implicitly valid.
			//The packet isn't valid, so reject it silently.
			terminateSock(source);
			return;
		}
		try {
			switch (parsedPacket.getType()) {
			case CRYPT:
				break;
			case GET:
				break;
			case GETID:
				break;
			case HELLO:
				handleHELLO(source, parsedPacket);
				break;
			case KEY:
				break;
			case MESSAGES:
				break;
			case PERSON:
				break;
			case SEND:
				break;
			default:
				break;
			}
		}
		catch (IOException e){
			e.printStackTrace(); //This is a problem.
		}
		
		
		//Leave this at the end: bear in mind we can block this function up as much as we damn well please:
		//all new connections are shoved into new threads.
		terminateSock(source);
		
	}
	
	private void terminateSock(Socket s) {
		try {
			if (!s.isClosed()) {
				s.close();
			}
		}
		catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	private void handleHELLO(Socket s, PacketParser triggerPacket) throws IOException {
		//We've received a HELLO from the server.
		UUID personUUID = triggerPacket.getSender();
		RSAKey userKey = Server.getAuthProvider().getUserPubKey(personUUID);
		if (userKey == null) {
			//New user (or sent a malformed public key last time).
			Connection.send(s, "NEW");
			//Now, await their response: if they vanish then it doesn't matter that much.
			String person = new String(Connection.readDat(s, 1024));
			PacketParser personPack = new PacketParser(person);
			String publicKey = new String(Connection.readDat(s, 65535)); //Massive read size since RSA keys are huge in comparison to names.
			PacketParser keyPack = new PacketParser(publicKey);
			if (personPack.isAuthenticated() && personPack.getType() == PacketType.PERSON) {
				if (keyPack.isAuthenticated() && keyPack.getType() == PacketType.CRYPT) {
					try {
						userKey = new RSAKey(keyPack.payload());
					} catch (MalformedKeyFileException e) {
						// Silently drop connection here.
						return;
					}
					Server.getAuthProvider().addUser(personUUID, userKey, person);
				}
			}
		}
		//Now, we generate the user a session token and send it to them
		byte[] userSes = Server.getAuthProvider().resetUserSessionKey(personUUID);
		System.out.println(Base64.getEncoder().encodeToString(userSes)); //This is a horrible idea, remove as soon as possible.
		String encryptedPayload = Base64.getEncoder().encodeToString(userKey.encrypt(userSes));
		Connection.send(s, "CHALLENGE " + encryptedPayload);
		//And done.
	}

}