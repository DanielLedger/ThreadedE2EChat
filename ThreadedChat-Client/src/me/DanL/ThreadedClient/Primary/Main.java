package me.DanL.ThreadedClient.Primary;

import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Scanner;
import java.util.UUID;

import me.DanL.E2EChat.CryptoUtils.BinaryUtils;
import me.DanL.E2EChat.CryptoUtils.PBKDF;
import me.DanL.E2EChat.CryptoUtils.RSAKey.MalformedKeyFileException;

public class Main {

	/**
	 * When true, all threads will kill themselves as fast as reasonably possible.
	 */
	private static boolean threadsDie = false;
	
	public static void main(String[] args) throws IOException {
		//First off, see if we have an info file
		File infoFile = new File("clientinfo.txt");
		File keyFile = new File("clientkey.crypt");
		UUID clientUid;
		byte[] clientSalt = new byte[32];
		char[] pass;
		String name;
		Console c = System.console();
		if (!infoFile.exists()) {
			//First run, so we'll need to collect this info ourselves.
			System.out.print("Welcome! As this is your first boot, we need to get some basic info. First off, what's your name?> ");
			name = c.readLine();
			clientUid = UUID.randomUUID();
			clientSalt = BinaryUtils.getSalt(32);
			char[] confPass;
			do {
				System.out.print("Please enter your master password. This needs to be strong, as with it, an attacker can impersonate you perfectly. In addition, you MUST be able to remember it: if you forget it, the password CANNOT BE RECOVERED.> ");
				pass = c.readPassword();
				System.out.print("Please confirm your password.> ");
				confPass = c.readPassword();
			}
			while (!areEqual(pass, confPass));
			System.out.println("Writing info file...");
			FileOutputStream fos = new FileOutputStream(infoFile);
			fos.write(name.getBytes());
			fos.write('\n');
			fos.write(clientUid.toString().getBytes());
			fos.close();
		}
		else {
			//Read from the file instead. We're assuming that the key file exists.
			Scanner s = new Scanner(infoFile);
			name = s.nextLine();
			clientUid = UUID.fromString(s.nextLine());
			s.close();
			FileInputStream fis = new FileInputStream(keyFile);
			fis.read(clientSalt);
			fis.close();
			System.out.println("Welcome " + name + "!");
			System.out.print("Please enter your master password> ");
			pass = c.readPassword();
		}
		//One way or another, we have the info we need.
		System.out.println("Deriving master key. This may take a few seconds...");
		byte[] masterKey = PBKDF.deriveKey(charsToBytes(pass), Arrays.copyOf(clientSalt, 32));
		System.out.println("Attempting to load master key from file...");
		ChatNetClient cnc = null; //Compile fails unless I put this???
		try {
			cnc = new ChatNetClient(keyFile, masterKey);
		} catch (IOException e) {
			//No master key file, create one.
			cnc = new ChatNetClient(keyFile, masterKey, clientSalt);
		} catch (MalformedKeyFileException | NullPointerException e) {
			//Password incorrect.
			System.out.println("Password incorrect! Program terminating...");
			System.exit(1);
		}
		//Finally, initialise the ChatNetworkClient
		cnc.init("localhost", 4444, clientUid, name);
		DownloadLoop dl = new DownloadLoop(cnc);
		Thread t = new Thread(dl);
		t.start();
		ChatClient cc = new ChatClient(masterKey, new File("userdata.csv"), cnc);
		/*
		System.out.print("Enter a UUID to send a message to, or enter to receive messages.> ");
		String add = c.readLine();
		if (!add.contentEquals("")) {
			cc.addUser(UUID.fromString(add), true);
			while (true) {
				System.out.print("Type your message.> ");
				cc.sendMsg(c.readLine(), UUID.fromString(add));
			}
		}
		else {
			while (true) {
				cc.handleUnreads();
				try {
					Thread.sleep(100);
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}*/
		ChatUI userInt = new ChatUI(cc, name, clientUid);
		while (!userInt.mainMenu(c)) {};
		System.out.println("Bye!");
		setThreadsDie(true);
	}
	
	private static class DownloadLoop implements Runnable{

		
		private ChatNetClient chatNetworker;
		
		DownloadLoop(ChatNetClient chatNet){
			chatNetworker = chatNet;
		}
		
		@Override
		public void run() {
			chatNetworker.retLoop();
		}
	}
	
	/**
	 * Test if two character arrays are equal or not.
	 * @param a
	 * @param b
	 */
	private static boolean areEqual(char[] a, char[] b) {
		if (a.length != b.length) {
			return false;
		}
		else {
			for (int i = 0; i<a.length; i++) {
				if (a[i] != b[i]) {
					return false;
				}
			}
			return true;
		}
	}
	
	private static byte[] charsToBytes(char[] a) {
		byte[] res = new byte[a.length];
		for (int i = 0;i < a.length; i++) {
			res[i] = (byte) Character.getNumericValue(a[i]);
			a[i] = 0;
		}
		return res;
	}

	/**
	 * @return the threadsDie
	 */
	public static boolean isThreadsDie() {
		return threadsDie;
	}

	/**
	 * @param threadsDie the threadsDie to set
	 */
	private static void setThreadsDie(boolean threadsDie) {
		Main.threadsDie = threadsDie;
	}

}
