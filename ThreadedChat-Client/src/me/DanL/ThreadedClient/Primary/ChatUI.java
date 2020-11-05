package me.DanL.ThreadedClient.Primary;

import java.io.Console;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import me.DanL.E2EChat.CryptoUtils.HMACUtils;

/**
 * Handles displaying things to the user.
 * @author daniel
 */
public class ChatUI {
	
	private ChatClient cc;
	
	private UUID ourUid;
	
	private String ourName;
	
	
	
	public ChatUI(ChatClient handler, String name, UUID uid) {
		cc = handler;
		ourName = name;
		ourUid = uid;
	}
	
	/**
	 * Renders the main menu (asking the user what they want to do).
	 * Should be called on loop until it returns true;
	 * 
	 * @return - If the user wants to quit or not.
	 */
	public boolean mainMenu(Console userInput) {
		System.out.println("--MAIN MENU--");
		System.out.println("0) Quit.");
		System.out.println("1) Talk to someone new.");
		System.out.println("2) View my info.");
		ArrayList<UUID> peopleToChat = new ArrayList<UUID>(cc.getUuids());
		int offset = 3;
		int offsetCtr = offset;
		for (UUID person: peopleToChat) {
			String personName = cc.getUsername(person);
			System.out.println(offsetCtr + ") View " + personName + ".");
			offsetCtr++;
		}
		int choiceI = Main.getNumber("Enter your choice> ", "Invalid option!");
		if (choiceI <= 0) {
			return true;
		}
		else if (choiceI == 1) {
			newPersonScreen();
		}
		else if (choiceI == 2) {
			userInfoScreen();
		}
		else {
			try {
				UUID viewing = peopleToChat.get(choiceI - offset);
				viewUserScreen(viewing);
			}
			catch (ArrayIndexOutOfBoundsException e) {
				System.out.println("Invalid option!");
			}
		}
		return false;
	}
	
	/**
	 * Screen for adding someone new to chat to.
	 */
	private void newPersonScreen() {
		System.out.print("Enter the UUID of the person you want to add> ");
		String uuidStr = System.console().readLine();
		try {
			UUID person = UUID.fromString(uuidStr);
			cc.addUser(person, false);
		}
		catch (IllegalArgumentException e) {
			System.out.println("Invalid UUID!");
		} catch (IOException e) {
			System.out.println("Communication to the server failed!");
		}
	}
	
	/**
	 * Our info
	 */
	private void userInfoScreen() {
		System.out.println("Your info: ");
		System.out.println("Name: " + ourName);
		System.out.println("UUID: " + ourUid);
	}
	
	/**
	 * User view screen, allowing you to chat with them and also verify keys.
	 */
	private void viewUserScreen(UUID who) {
		System.out.println("Viewing " + who.toString());
		while (true) {
			System.out.println("0) Back");
			System.out.println("1) View chat");
			System.out.println("2) Verify keys");
			int choice = Main.getNumber("Enter your choice> ", "Invalid choice!");
			if (choice == 0) {
				break;
			}
			else if (choice == 1) {
				displayChat(who);
			}
			else if (choice == 2) {
				verifyUser(who);
			}
			else {
				System.out.println("Invalid choice!");
			}
		}
	}
	
	/**
	 * Creates the verification screen for checking a user's public key.
	 * @param who - The user to check.
	 */
	private void verifyUser(UUID who) {
		Console userInput = System.console();
		System.out.print("Please enter a word or phrase to mix in to the key verification. This doesn't need to be secret, but you must both know it: ");
		String psk = userInput.readLine();
		System.out.println("Computing key hash. This may take up to 20 seconds...");
		byte[] keyHash = cc.getKeySummary(who, psk);
		System.out.println("Now, please enter a series of numbers and check with the other person that your UUIDs are the same.");
		System.out.println("You should check at least 2 numbers, 5 if you feel paranoid.");
		int verifNum;
		do {
			verifNum = Main.getNumber("Enter the UUID number you want to view, or -1 to quit: ", "That's not a number!");
			byte[] asBytes = Integer.toString(verifNum).getBytes();
			byte[] summedDat = HMACUtils.hmac(keyHash, asBytes);
			UUID outputUid = UUID.nameUUIDFromBytes(summedDat);
			System.out.println("When N=" + verifNum + ", UUID=" + outputUid.toString());
		}
		while (verifNum >= 0);
	}
	
	/**
	 * Shows the chat for a user.
	 * @param who - The user we are chatting to.
	 */
	private void displayChat(UUID who) {
		Lock l = new ReentrantLock(); //When we want to kill the message output thread, we lock this lock, which it will then detect and terminate.
		System.out.println("---CHAT WITH " + cc.getUsername(who) + "---");
		System.out.println("Type any message and hit ENTER to send. Typing /back will take you to the previous window.");
		MessageDisplay md = new MessageDisplay(l, who);
		Thread displayThread = new Thread(md);
		//Start the display thread first
		displayThread.start();
		//Now, we get to our input bit.
		while (true) {
			String inp = System.console().readLine();
			if (inp.contentEquals("/back")) {
				l.lock(); //This should cause the other thread to kill itself.
				break; 
			}
			else {
				try {
					cc.sendMsg(inp, who);
					//System.out.println("ME> " + inp);
				} catch (IOException e) {
					System.out.println("SYSTEM> The message could not be delivered. Are you sure you're connected to a server?");
				}
			}
		}
	}
	
	private class MessageDisplay implements Runnable{

		private Lock terminate;
		
		private UUID personPrintingFor;
		
		private String personName;
		
		MessageDisplay(Lock control, UUID who){
			terminate = control;
			personPrintingFor = who;
			personName = cc.getUsername(who);
		}
		
		@Override
		public void run() {
			while (terminate.tryLock()) {
				terminate.unlock(); //Don't actually hold the lock.
				try {
					Thread.sleep(1100);
				} catch (InterruptedException e) {
					//???
				}
				List<Message> unread = cc.getUnreadFrom(personPrintingFor);
				if (unread == null) {continue;}
				for (Message m: unread) {
					String content = cc.decryptMessage(m, personPrintingFor);
					System.out.println(personName + "> " + content);
				}
			}
		}
		
	}
	
}
