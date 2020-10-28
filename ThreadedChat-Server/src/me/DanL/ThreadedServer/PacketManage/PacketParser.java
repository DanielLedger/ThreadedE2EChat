package me.DanL.ThreadedServer.PacketManage;

import java.util.Base64;
import java.util.UUID;

import me.DanL.ThreadedServer.Primary.Server;

/**
 * A packet parser that parses all incoming packets into a usable object.
 * @author daniel
 *
 */
public class PacketParser {
	
	public enum PacketType{
		HELLO,
		PERSON,
		CRYPT,
		GET,
		GETID,
		KEY,
		MESSAGES,
		SEND
	}
	
	private String payload = "";
	
	private UUID sender = null;
	
	private int packetNum;
	
	private byte[] authToken;
	
	/**
	 * If the packet has valid structure.
	 */
	private boolean valid = false;
	/**
	 * If the packet contains a valid authentication tag.
	 */
	private boolean authenticated = false;
	
	private PacketType typeOf;
	
	/**
	 * Test if the given packet type needs a session token attached to it. See spec.
	 * @param pt - What type to check.
	 * @return
	 */
	public static boolean requiresAuth(PacketType pt) {
		switch (pt) {
		case HELLO:
			return false;
		case PERSON:
			return false;
		case CRYPT:
			return false;
		default:
			return true;
		}
	}
	
	public PacketParser(String packetData) {
		String[] parts = packetData.trim().split(" ");
		String type = parts[0];
		try {
			typeOf = PacketType.valueOf(type);
		}
		catch (IllegalArgumentException e) {
			return; //Invalid packet type.
		}
		try {
			switch (typeOf) {
			case CRYPT:
				payload = parts[1];
				break;
			case GET:
				payload = parts[1];
				packetNum = Integer.parseInt(parts[2]);
				authToken = Base64.getDecoder().decode(parts[3]);
				sender = UUID.fromString(parts[4]);
				break;
			case GETID:
				payload = parts[1];
				packetNum = Integer.parseInt(parts[2]);
				authToken = Base64.getDecoder().decode(parts[3]);
				sender = UUID.fromString(parts[4]);
				break;
			case HELLO:
				sender = UUID.fromString(parts[1]);
				break;
			case KEY:
				payload = parts[1];
				packetNum = Integer.parseInt(parts[2]);
				authToken = Base64.getDecoder().decode(parts[3]);
				sender = UUID.fromString(parts[4]);
				break;
			case MESSAGES:
				packetNum = Integer.parseInt(parts[1]);
				authToken = Base64.getDecoder().decode(parts[2]);
				sender = UUID.fromString(parts[3]);
				break;
			case PERSON:
				payload = parts[1];
				break;
			case SEND:
				payload = parts[1] + " " + parts[2];
				packetNum = Integer.parseInt(parts[3]);
				authToken = Base64.getDecoder().decode(parts[4]);
				sender = UUID.fromString(parts[5]);
				break;
			}
		}
		catch (ArrayIndexOutOfBoundsException | NumberFormatException e) {
			//Failed to parse packet correctly, so just return.
			e.printStackTrace();
			return;
		}
		valid = true; //Packet has the required structure
		authenticated = (!requiresAuth(typeOf)) || Server.getAuthProvider().packetAuthed(payload, sender, packetNum, authToken);
	}
	
	public UUID getSender() {
		return sender;
	}

	@Override
	public String toString() {
		String desc = "";
		if (!valid) {
			return "Invalid packet!\n";
		}
		else if (!authenticated) {
			desc = "Unauthenticated packet:\n";
		}
		else {
			desc = "Authenticated packet:\n";
		}
		desc += "Packet type: " + typeOf.toString();
		if (sender != null) {
			desc += "\nSender ID: " + sender.toString();
		}
		else {
			desc += "\nNo declared sender.";
		}
		desc += "\nPacket payload: " + payload;
		desc += "\n";
		return desc;
	}

	/**
	 * @return the valid
	 */
	public boolean isValid() {
		return valid;
	}

	/**
	 * @return the authenticated
	 */
	public boolean isAuthenticated() {
		return authenticated;
	}
	
	public PacketType getType() {
		return typeOf;
	}
	
	public String payload() {
		return payload;
	}
}
