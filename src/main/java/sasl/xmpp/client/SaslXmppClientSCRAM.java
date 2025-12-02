package sasl.xmpp.client;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jivesoftware.smack.tcp.XMPPTCPConnectionConfiguration;

public class SaslXmppClientSCRAM extends SaslXmppClient {

    private static final Logger log = LogManager.getLogger(SaslXmppClientSCRAM.class);

    private static final String USERNAME_ALICE = "alice";
    private static final String PASSWORD_ALICE = "alicepass";

    @Override
    protected XMPPTCPConnectionConfiguration.Builder configureConnectionFactory(XMPPTCPConnectionConfiguration.Builder connectionConfigurationBuilder) {
        return connectionConfigurationBuilder
                .setUsernameAndPassword(USERNAME_ALICE, PASSWORD_ALICE);
    }

    @Override
    public void run() throws Exception {
        super.run();
    }

    public static void main(String[] args) throws Exception {
        new SaslXmppClientSCRAM().run();
    }
}
