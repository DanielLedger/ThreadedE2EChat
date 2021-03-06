package me.DanL.ThreadedServer.Primary;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;
import java.util.Scanner;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import me.DanL.ThreadedServer.UserManagement.Authenticator;

public class Server {
	private static Authenticator authProvider;
	
	private static File msgSaveFile;

	//We were getting some exceedingly odd issues with messages being lost to the aether despite being supposedly received, so this may help.
	private static ConcurrentHashMap<UUID, List<String>> userMsgs = new ConcurrentHashMap<UUID, List<String>>();
	
	private static boolean printLogs = true;
	
	/**
	 * @return the authProvider
	 */
	public static Authenticator getAuthProvider() {
		return authProvider;
	}

	/**
	 * @param authProvider the authProvider to set
	 */
	public static void setAuthProvider(Authenticator authProvider) {
		Server.authProvider = authProvider;
	}

	/**
	 * @param printLogs the printLogs to set
	 */
	public static void setPrintLogs(boolean printLogs) {
		Server.printLogs = printLogs;
	}
	
	/**
	 * Prints debug logs if they are enabled.
	 * @param out
	 */
	public static void debugOutput(String out) {
		if (printLogs) {
			System.out.println(out);
		}
	}
	
	/**
	 * Loads the pending messages for users from disk.
	 * @throws FileNotFoundException 
	 */
	public static void loadPendingMsgs() throws FileNotFoundException {
		if (!msgSaveFile.exists()) {
			return; //Nothing to load.
		}
		Scanner fileReader = new Scanner(msgSaveFile);
		while (fileReader.hasNextLine()) {
			//Assuming a name,UUID pair
			String[] parts = fileReader.nextLine().trim().split(",");
			UUID uid = UUID.fromString(parts[0]); //Should always be valid.
			ArrayList<String> pending = new ArrayList<String>();
			for (int i = 1; i<parts.length; i++) {
				pending.add(parts[i]);
			}
			userMsgs.put(uid,pending);
		}
		fileReader.close();
	}

	/**
	 * Saves pending messages to disk.
	 * @throws IOException
	 */
	public static void savePendingMsgs() throws IOException {
		FileOutputStream fos = new FileOutputStream(msgSaveFile);
		for (Entry<UUID, List<String>> e: userMsgs.entrySet()) {
			String toWrite = e.getKey() + "," + String.join(",", e.getValue().toArray(new String[1])) + "\n";
			fos.write(toWrite.getBytes());
		}
		fos.close();
	}
	
	/**
	 * Adds a pending message for a given user.
	 * @param toWho - Who was the message sent to?
	 * @param msg - What's the message. This better be base64 encoded else we will have issues.
	 */
	public static void addPendingMsg(UUID toWho, String msg) {
		synchronized(userMsgs) {
			//System.out.println("Started adding message...");
			List<String> msgList = userMsgs.getOrDefault(toWho, new ArrayList<String>());
			msgList.add(msg);
			userMsgs.put(toWho, msgList);
			try {
				savePendingMsgs();
			} catch (IOException e) {
				e.printStackTrace();
			}
			//System.out.println("Ended adding messages...");
		} //Lock needed for whole operation to prevent weird things from happening.
	}
	
	/**
	 * Gets and wipes the messages to a person.
	 * @param toWho - Who's messages are we getting?
	 * @return - The user's messages they need to be sent.
	 */
	public static List<String> getAndClearMsgs(UUID toWho){
		synchronized(userMsgs) {
			//System.out.println("Started getting messages...");
			List<String> removed = userMsgs.remove(toWho);
			try {
				savePendingMsgs();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			//System.out.println("Ended getting messages...");
			return removed;
		}
	}

	/**
	 * @param msgSaveFile the msgSaveFile to set
	 */
	public static void setMsgSaveFile(File msgSaveFile) {
		Server.msgSaveFile = msgSaveFile;
	}
}
