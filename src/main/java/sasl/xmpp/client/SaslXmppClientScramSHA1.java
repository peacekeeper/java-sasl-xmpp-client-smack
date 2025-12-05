package sasl.xmpp.client;

import demo.sasl.client.SaslClientCallbackHandler;
import demo.sasl.client.integration.UserIntegrationDemoUsername;
import demo.sasl.client.integration.UserIntegrationInteractive;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jivesoftware.smack.tcp.XMPPTCPConnectionConfiguration;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

public class SaslXmppClientScramSHA1 extends SaslXmppClient {

    private static final Logger log = LogManager.getLogger(SaslXmppClientScramSHA1.class);

    protected SaslXmppClientScramSHA1(boolean interactive) {
        super(interactive);
    }

    @Override
    protected XMPPTCPConnectionConfiguration.Builder configureConnectionFactory(XMPPTCPConnectionConfiguration.Builder connectionConfigurationBuilder) throws UnsupportedCallbackException {
        SaslClientCallbackHandler saslClientCallbackHandler = new SaslClientCallbackHandler(this.isInteractive() ? new UserIntegrationInteractive() : new UserIntegrationDemoUsername());
        NameCallback nc = new NameCallback("name");
        PasswordCallback pc = new PasswordCallback("password", false);
        saslClientCallbackHandler.handle(new Callback[] { nc, pc });
        String username = nc.getName();
        String password = pc.getPassword() == null ? null : new String(pc.getPassword());
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
