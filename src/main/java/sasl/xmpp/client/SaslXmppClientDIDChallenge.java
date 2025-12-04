package sasl.xmpp.client;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jivesoftware.smack.SASLAuthentication;
import org.jivesoftware.smack.tcp.XMPPTCPConnectionConfiguration;
import sasl.mechanism.did.DIDChallengeSaslProvider;
import sasl.xmpp.client.debug.SaslClientDebug;

import java.security.Security;

public class SaslXmppClientDIDChallenge extends SaslXmppClient {

    private static final Logger log = LogManager.getLogger(SaslXmppClientDIDChallenge.class);

    static {
        Security.addProvider(new DIDChallengeSaslProvider());
    }

    static {
        SaslClientDebug.logSaslClientFactoriesAndMechanisms();
    }

    protected SaslXmppClientDIDChallenge(boolean interactive) {
        super(interactive);
    }

    @Override
    protected XMPPTCPConnectionConfiguration.Builder configureConnectionFactory(XMPPTCPConnectionConfiguration.Builder connectionConfigurationBuilder) {
        SASLAuthentication.unregisterSASLMechanism(SASLDIDChallengeJavaXMechanism.class.getName());
        SASLAuthentication.registerSASLMechanism(new SASLDIDChallengeJavaXMechanism(this.isInteractive()));
        log.debug("SASL mechanisms: " + SASLAuthentication.getRegisterdSASLMechanisms());
        return connectionConfigurationBuilder
                .allowEmptyOrNullUsernames()
                .addEnabledSaslMechanism("DID-CHALLENGE");
    }

    @Override
    public void run() throws Exception {
        super.run();
    }

    public static void main(String[] args) throws Exception {
        new SaslXmppClientDIDChallenge(false).run();
    }
}