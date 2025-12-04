package sasl.xmpp.client;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class Main {

    public static void main(String[] args) throws Exception {
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("SASL mechanism? 1=SCRAM-SHA-1, 2=DID-CHALLENGE");
        String lineSaslMechanism = bufferedReader.readLine();
        System.out.println("User integration? 1=Demo, 2=Interactive");
        String lineUserIntegration = bufferedReader.readLine();
        boolean interactive = switch(lineUserIntegration) {
            case "1" -> false;
            case "2" -> true;
            default -> { System.out.println("Invalid choice: " + lineUserIntegration); System.exit(1); yield false; }
        };
        SaslXmppClient saslXmppClient = switch (Integer.parseInt(lineSaslMechanism)) {
            case 1 -> new SaslXmppClientScramSHA1(interactive);
            case 2 -> new SaslXmppClientDIDChallenge(interactive);
            default -> { System.out.println("Invalid choice: " + lineSaslMechanism); System.exit(1); yield null; }
        };
        saslXmppClient.run();
    }
}