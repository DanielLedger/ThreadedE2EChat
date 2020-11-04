package me.DanL.ThreadedServer.PacketManage;

import java.io.IOException;
import java.net.Socket;
import java.util.Base64;
import java.util.List;
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
		Server.debugOutput("Got packet: " + data);
		PacketParser parsedPacket = new PacketParser(data);
		Server.debugOutput("Packet parse result:");
		Server.debugOutput(parsedPacket.toString());
		if (!parsedPacket.isAuthenticated()) { //Authenticated packets are implicitly valid.
			//The packet isn't valid, so reject it silently.
			Server.debugOutput("Unauthenticated packet, rejecting...");
			terminateSock(source);
			return;
		}
		try {
			switch (parsedPacket.getType()) {
			case CRYPT: //Packet should never be received without explanation.
				Server.debugOutput("CRYPT packet received unexpectedly, exiting...");
				break;
			case GET:
				handleGET(source, parsedPacket);
				break;
			case GETID:
				handleGETID(source, parsedPacket);
				break;
			case HELLO:
				handleHELLO(source, parsedPacket);
				break;
			case KEY:
				handleKEY(source, parsedPacket);
				break;
			case MESSAGES:
				handleMESSAGES(source, parsedPacket);
				break;
			case PERSON: //Packet should never be received without explanation.
				Server.debugOutput("PERSON packet received unexpectedly, exiting...");
				break;
			case SEND:
				handleSEND(source, parsedPacket);
				break;
			default:
				break;
			}
		}
		catch (IOException e){
			Server.debugOutput("ERROR!");
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
			Server.debugOutput("New user with ID: " + triggerPacket.getSender().toString());
			Connection.send(s, "NEW");
			//Now, await their response: if they vanish then it doesn't matter that much.
			String person = new String(Connection.readDat(s, 1024));
			PacketParser personPack = new PacketParser(person);
			String publicKey = new String(Connection.readDat(s, 65535)); //Massive read size since RSA keys are huge in comparison to names.
			PacketParser keyPack = new PacketParser(publicKey);
			if (personPack.isAuthenticated() && personPack.getType() == PacketType.PERSON) {
				if (keyPack.isAuthenticated() && keyPack.getType() == PacketType.CRYPT) {
					try {
						userKey = new RSAKey(keyPack.payload(), false);
					} catch (MalformedKeyFileException e) {
						// Silently drop connection here.
						return;
					}
					Server.debugOutput("Adding user...");
					Server.getAuthProvider().addUser(personUUID, userKey, personPack.payload());
				}
			}
		}
		//Now, we generate the user a session token and send it to them
		byte[] userSes = Server.getAuthProvider().resetUserSessionKey(personUUID);
		System.out.println(Base64.getEncoder().encodeToString(userSes)); //This is a horrible idea, remove as soon as possible.
		String encryptedPayload = Base64.getEncoder().encodeToString(userKey.encrypt(userSes));
		Server.debugOutput("Sending user challenge...");
		Connection.send(s, "CHALLENGE " + encryptedPayload);
		//And done.
	}
	
	private void handleKEY(Socket s, PacketParser trigger) throws IOException {
		String strUid = trigger.payload();
		UUID lookup = null;
		try {
			lookup = UUID.fromString(strUid);
		}
		catch (IllegalArgumentException e) {
			Server.debugOutput("Bad UUID provided, sending null key...");
			Connection.send(s, "PKEY null");
		}
		RSAKey key = Server.getAuthProvider().getUserPubKey(lookup);
		if (key == null) {
			Server.debugOutput("Bad user provided, sending null key...");
			Connection.send(s, "PKEY null");
		}
		else {
			Server.debugOutput("Sending public key...");
			Connection.send(s, "PKEY " + key.savePublicToString().replace(" ", "").replace("\n", "")); //Sends the user's public RSA key.
		}
	}
	
	private void handleGET(Socket s, PacketParser trigger) throws IOException {
		String nameToCheck = trigger.payload();
		UUID result = Server.getAuthProvider().getUid(nameToCheck);
		Connection.send(s, "USER " + result.toString());
	}
	
	private void handleGETID(Socket s, PacketParser trigger) throws IOException {
		try {
			UUID u = UUID.fromString(trigger.payload());
			String result = Server.getAuthProvider().getName(u);
			Connection.send(s, "USER " + result);
		}
		catch (IllegalArgumentException e) {
			Connection.send(s, "USER null"); //Invalid UUID looked up.
		}
	}
	
	private void handleSEND(Socket s, PacketParser trigger) {
		String msgRaw = trigger.payload();
		try {
			String[] sp = msgRaw.split(" ");
			UUID target = UUID.fromString(sp[1]);
			String sent = sp[0];
			Server.addPendingMsg(target, sent);
		}
		catch (IllegalArgumentException e) {
			//Silently reject due to invalid ID.
		}
		
	}
	
	private void handleMESSAGES(Socket s, PacketParser trigger) throws IOException {
		List<String> pendingForClient = Server.getAndClearMsgs(trigger.getSender());
		//System.out.println("Sending messages...");
		if (pendingForClient == null) {
			//Nothing to send to the client
			//System.out.println("Nothing to send to " + trigger.getSender());
			Connection.send(s, "LENGTH 0\n");
			return;
		}
		String sendStr = "";
		for (String msg: pendingForClient) {
			sendStr += "MSG " + msg + ";";
		}
		System.out.println(sendStr);
		Connection.send(s, "LENGTH " + sendStr.length() + "\n");
		Connection.send(s, sendStr);
	}

}
