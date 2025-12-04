package sasl.xmpp.client;

import demo.sasl.client.SaslClientCallbackHandler;
import demo.sasl.client.integration.UserIntegrationDemoUsername;
import demo.sasl.client.integration.UserIntegrationInteractive;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jivesoftware.smack.tcp.XMPPTCPConnectionConfiguration;

public class SaslXmppClientScramSHA1 extends SaslXmppClient {

    private static final Logger log = LogManager.getLogger(SaslXmppClientScramSHA1.class);

    protected SaslXmppClientScramSHA1(boolean interactive) {
        super(interactive);
    }

    @Override
    protected XMPPTCPConnectionConfiguration.Builder configureConnectionFactory(XMPPTCPConnectionConfiguration.Builder connectionConfigurationBuilder) {
        SaslClientCallbackHandler saslClientCallbackHandler = new SaslClientCallbackHandler(this.isInteractive() ? new UserIntegrationInteractive() : new UserIntegrationDemoUsername());
        String username = saslClientCallbackHandler.getUserIntegration().getName();
        String password = saslClientCallbackHandler.getUserIntegration().getPassword();
        return connectionConfigurationBuilder
                .setUsernameAndPassword(username, password);
    }

    @Override
    public void run() throws Exception {
        super.run();
    }

    public static void main(String[] args) throws Exception {
        new SaslXmppClientScramSHA1(false).run();
    }
}
