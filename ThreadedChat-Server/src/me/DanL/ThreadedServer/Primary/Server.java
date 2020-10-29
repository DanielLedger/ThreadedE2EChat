package me.DanL.ThreadedServer.Primary;

import me.DanL.ThreadedServer.UserManagement.Authenticator;

public class Server {
	private static Authenticator authProvider;

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
}
