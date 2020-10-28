package me.DanL.ThreadedServer.Primary;

import me.DanL.ThreadedServer.UserManagement.Authenticator;

public class Server {
	private static Authenticator authProvider;

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
}
