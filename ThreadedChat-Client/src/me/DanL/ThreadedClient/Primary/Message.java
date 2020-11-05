package me.DanL.ThreadedClient.Primary;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.AEADBadTagException;

import me.DanL.E2EChat.CryptoUtils.AES;
import me.DanL.E2EChat.CryptoUtils.BinaryUtils;
import me.DanL.E2EChat.CryptoUtils.HMACUtils;

/**
 * Represents a message from another user, in the sense of actual text based message.
 * @author daniel
 *
 */
public class Message {
	
	byte[] encryptedContent;
	
	byte[] msgNum;
	
	byte[] msgIv;
	
	/**
	 * Initialises an encrypted message as a received one.
	 * @param raw - Base64 encoded message.
	 */
	public Message(String raw) {
		//Expecting Base64 blob of 4 byte message number, 16 byte IV and then arbitrary cipher.
		byte[] rawContents = Base64.getDecoder().decode(raw);
		msgNum = Arrays.copyOfRange(rawContents, 0, 4);
		msgIv = Arrays.copyOfRange(rawContents, 4, 20);
		encryptedContent = Arrays.copyOfRange(rawContents, 20, rawContents.length);
	}
	
	/**
	 * Initialise a message with plaintext.
	 * @param msg - The message to send.
	 * @param ctr - The message number.
	 */
	public Message(String msg, int ctr, byte[] masterKey) {
		ByteBuffer bb = ByteBuffer.allocate(4);
		bb.putInt(ctr);
		msgNum = bb.array();
		msgIv = BinaryUtils.getSalt(16);
		encryptMsg(msg, masterKey);
	}
	
	/**
	 * Encrypts the message and stores it to encryptedContent
	 * @param msgData
	 */
	private void encryptMsg(String msgData, byte[] masterSecret) {
		try {
			encryptedContent = AES.encryptGCM(HMACUtils.hmac(masterSecret, msgNum), msgIv, msgData.getBytes());
		} catch (InvalidKeyException e) {
			//??
			e.printStackTrace();
		}
	}
	
	/**
	 * Gets the message stored by this object.
	 * @param masterSecret - The 32 byte master secret.
	 * @return - The message, or a user-friendly error.
	 */
	public String getMsgContent(byte[] masterSecret) {
		byte[] msgKey = HMACUtils.hmac(masterSecret, msgNum);
		try {
			byte[] rawDecrypt = AES.decryptGCM(msgKey, msgIv, encryptedContent);
			return new String(rawDecrypt);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			return "Something broke!"; //This shouldn't happen.
		} catch (AEADBadTagException e) {
			return "Message could not be decrypted! This could be a result of it being modified in transit, or something else.";
		}
	}
	
	/**
	 * Returns the encrypted message as base64, suitable for sending.
	 * @return
	 */
	public String getSerialized() {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try {
			baos.write(msgNum);
			baos.write(msgIv);
			baos.write(encryptedContent);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return Base64.getEncoder().encodeToString(baos.toByteArray());
	}
}
