package me.DanL.PacketManager;
import java.io.Console;
import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;

public class Connection {
	
	/**
	 * Sends a packet. Does not listen for a response: it will close the socket as soon as the packet is sent.
	 * @param ip - What IP you want to send the packet to.
	 * @param port - What port the packet is being sent to.
	 * @param data - What data is in the packet.
	 * @throws IOException 
	 * @throws UnknownHostException 
	 */
	public static void send(String ip, int port, String data) throws UnknownHostException, IOException {
		Socket commSoc = new Socket(ip, port);
		send(commSoc, data);
		commSoc.close();
	}
	
	/**
	 * Sends a packet using the already connected socket. Will not close the socket.
	 * @param dataTransfer
	 * @param data
	 * @throws IOException 
	 */
	public static void send(Socket dataTransfer, String data) throws IOException {
		dataTransfer.getOutputStream().write(data.getBytes());
	}
	
	/**
	 * Waits until a connection is found, then calls the {@link DataReceiver#getData(Socket, String)} of the passed DataReceiver.
	 * The method is called in a seperate thread, so exercise caution when handling objects etc.
	 * @param listenPort - What port to listen on? Set above 1024 to avoid clashes.
	 * @param maxDataLen - What's the maximum amount of data to read off the socket?
	 * @param onPacketGet - The object we use to hold the method we call when we get a packet.
	 * @throws IOException 
	 */
	public static void onRecv(int listenPort, int maxDataLen, DataReceiver onPacketGet, boolean thread) throws IOException {
		ServerSocket ss = new ServerSocket(listenPort);
		Socket clientSock = ss.accept();
		Runnable r = () -> {
			try {
				onPacketGet.getData(clientSock, new String(readDat(clientSock, maxDataLen)));
			} catch (IOException e) {
				e.printStackTrace();
			}
		};
		if (thread) {
			Thread t = new Thread(r);
			t.run();
		}
		else {
			r.run(); //Same thread.
		}
		ss.close();
	}
	
	/**
	 * Since this is a faff and we do it multiple times, define a seperate method.
	 * @param s - The socket we're getting data from.
	 * @param maxLen - The maximum length of the data to download.
	 * @return - The raw data from the socket.
	 * @throws IOException 
	 */
	public static byte[] readDat(Socket s, int maxLen) throws IOException {
		InputStream bos = s.getInputStream();
		byte[] rawData = new byte[maxLen];
		int howMuch = bos.read(rawData);
		byte[] truncated = new byte[howMuch];
		for (int i = 0; i<howMuch; i++) {
			truncated[i] = rawData[i]; //Trims the trailing null bytes off truncated.
		}
		return truncated;
	}
	
	/**
	 * Sends some data, and then calls a function on response.
	 * Function is called in a seperate thread, so be careful!
	 * @param ip - The IP to connect to.
	 * @param port - The port to connect to.
	 * @param maxDataLen - The maximum amount of data to receive.
	 * @param data - The data to send.
	 * @param onReplyGet - The object holding the function we call when we get a reply.
	 * @throws IOException 
	 * @throws UnknownHostException 
	 */
	public static void sendRecv(String ip, int port, int maxDataLen, String data, DataReceiver onReplyGet) throws UnknownHostException, IOException {
		Socket commSoc = new Socket(ip, port);
		send(commSoc, data);
		String gotBack = new String(readDat(commSoc, maxDataLen));
		Runnable r = () -> onReplyGet.getData(commSoc, gotBack);
		Thread t = new Thread(r);
		t.run();
		commSoc.close();
	}
	
	/**
	 * Testing only: do not use.
	 * @author daniel
	 *
	 */
	private static class TestRecv implements DataReceiver{

		@Override
		public void getData(Socket source, String data) {
			System.out.println("Got data: " + data);
		}
		
	}
	
	/**
	 * Testing purposes only.
	 * @param args - Command line arguments.
	 * @throws IOException 
	 * @throws UnknownHostException 
	 */
	public static void main(String[] args) throws UnknownHostException, IOException {
		Console io = System.console();
		if (io == null) {
			System.exit(1);
		}
		TestRecv dr = new TestRecv();
		io.printf("%s", "Testing data send only to localhost at port 4444. Press enter to continue: ");
		io.readLine();
		Connection.send("localhost", 4444, "Hello!");
		io.printf("%s", "Testing data receive only. Program will continue when data received at port 4444:");
		Connection.onRecv(4444, 1024, dr, false);
		io.printf("%s", "Testing data sendRecv. Data will be sent to localhost at port 4444. Press enter to continue: ");
		io.readLine();
		Connection.sendRecv("localhost", 4444, 1024, "Hello!", dr);
		io.printf("%s", "All tests passed! Terminating...");
	}
	
}
