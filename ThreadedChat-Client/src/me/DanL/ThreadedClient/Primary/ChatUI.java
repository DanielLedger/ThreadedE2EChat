package me.DanL.ThreadedClient.Primary;

import java.io.Console;
import java.util.ArrayList;
import java.util.UUID;

import me.DanL.E2EChat.CryptoUtils.HMACUtils;

/**
 * Handles displaying things to the user.
 * @author daniel
 */
public class ChatUI {
	
	private ChatClient cc;
	
	private UUID ourUid;
	
	private String ourName;
	
	/**
	 * Read a number from console. Keeps asking until a number is entered.
	 * @param prompt - The message to send to the user.
	 * @param err - The message to send if a not-number is entered.
	 * @return - The number the user entered.
	 */
	private int getNumber(String prompt, String err) {
		System.out.print(prompt);
		Console c = System.console();
		int resp;
		while (true) {
			try {
				resp = Integer.parseInt(c.readLine());
				break;
			}
			catch (NumberFormatException e) {
				System.out.println(err);
			}
		}
		return resp;
	}
	
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
		int choiceI = getNumber("Enter your choice> ", "Invalid option!");
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
		System.out.println("Adding a new person...");
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
		verifyUser(who);
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
			verifNum = getNumber("Enter the UUID number you want to view, or -1 to quit: ", "That's not a number!");
			byte[] asBytes = Integer.toString(verifNum).getBytes();
			byte[] summedDat = HMACUtils.hmac(keyHash, asBytes);
			UUID outputUid = UUID.nameUUIDFromBytes(summedDat);
			System.out.println("When N=" + verifNum + ", UUID=" + outputUid.toString());
		}
		while (verifNum >= 0);
	}
	
}
