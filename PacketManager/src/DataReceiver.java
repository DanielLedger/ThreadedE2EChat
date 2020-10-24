import java.net.Socket;

public interface DataReceiver {
	/**
	 * Run by {@link Connection#onRecv(int, int, DataReceiver)} when it gets a packet.
	 * Note that the method will block until we're done, so consider starting a thread and returning instantly from here.
	 * @param source - The client socket that we got this data from.
	 * @param data - The string representation of the data we've received.
	 */
	abstract void getData(Socket source, String data);
}
