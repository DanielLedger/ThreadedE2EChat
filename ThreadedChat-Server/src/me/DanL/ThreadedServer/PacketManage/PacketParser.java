package me.DanL.ThreadedServer.PacketManage;

import java.util.Base64;
import java.util.UUID;

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
	
	private String payload;
	
	private UUID sender;
	
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
		String[] parts = packetData.split(packetData);
		String type = parts[0];
		typeOf = PacketType.valueOf(type);
		if (typeOf == null) {
			return;
		}
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
			payload = parts[1];
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
	
	@Override
	public String toString() {
		return "";
	}
}
