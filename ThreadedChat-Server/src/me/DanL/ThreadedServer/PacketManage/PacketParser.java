package me.DanL.ThreadedServer.PacketManage;

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
	
	private boolean parsed;
	private boolean valid;
	
	public PacketParser(String packetData) {
		
	}
}
