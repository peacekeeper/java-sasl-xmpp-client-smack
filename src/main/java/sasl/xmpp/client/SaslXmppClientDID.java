package sasl.xmpp.client;

import demo.sasl.client.SaslClientCallbackHandler;
import demo.sasl.client.integration.UserIntegrationInteractive;
import demo.sasl.client.integration.UserIntegrationWithDID;
import org.apache.commons.codec.binary.Hex;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jivesoftware.smack.SASLAuthentication;
import org.jivesoftware.smack.SmackException;
import org.jivesoftware.smack.sasl.SASLMechanism;
import org.jivesoftware.smack.sasl.javax.SASLJavaXMechanism;
import org.jivesoftware.smack.sasl.javax.SmackJavaxSaslException;
import org.jivesoftware.smack.tcp.XMPPTCPConnectionConfiguration;
import sasl.mechanism.did.DIDChallengeSaslProvider;
import sasl.mechanism.did.client.DIDChallengeSaslClient;
import sasl.xmpp.client.debug.SaslClientDebug;

import javax.security.auth.callback.*;
import javax.security.sasl.*;
import java.io.IOException;
import java.security.Security;
import java.util.Map;

public class SaslXmppClientDID extends SaslXmppClient {

    private static final Logger log = LogManager.getLogger(SaslXmppClientDID.class);

    static {
        Security.addProvider(new DIDChallengeSaslProvider());
    }

    static {
        SaslClientDebug.logSaslClientFactoriesAndMechanisms();
    }

    static {
        SASLAuthentication.registerSASLMechanism(new SASLDIDChallengeJavaXMechanism());
        log.debug("SASL mechanisms: " + SASLAuthentication.getRegisterdSASLMechanisms());
    }

    @Override
    protected XMPPTCPConnectionConfiguration.Builder configureConnectionFactory(XMPPTCPConnectionConfiguration.Builder connectionConfigurationBuilder) {
        return connectionConfigurationBuilder
                .allowEmptyOrNullUsernames()
                .addEnabledSaslMechanism("DID-CHALLENGE");
    }

    @Override
    public void run() throws Exception {
        super.run();
    }

    public static void main(String[] args) throws Exception {
        new SaslXmppClientDID().run();
    }

    /*
     * Helper classes
     */

    private static class SASLDIDChallengeJavaXMechanism extends SASLJavaXMechanism {

        @Override
        public String getName() {
            return DIDChallengeSaslProvider.MECHANISM_NAME;
        }

        @Override
        public int getPriority() {
            return 0;
        }

        @Override
        protected SASLMechanism newInstance() {
            return new SASLDIDChallengeJavaXMechanism();
        }

        @Override
        public boolean requiresPassword() {
            return false;
        }

        @Override
        protected void authenticateInternal() throws SmackJavaxSaslException {
            String[] mechanisms = { getName() };
            Map<String, String> props = getSaslProps();
            String authzid = null;
            if (authorizationId != null) {
                authzid = authorizationId.toString();
            }
            try {
                sc = Sasl.createSaslClient(mechanisms, authzid, "xmpp", getServerName().toString(), props,
                        new SaslClientCallbackHandler(new UserIntegrationWithDID()));
            }
            catch (SaslException e) {
                throw new SmackJavaxSaslException(e);
            }
        }

        @Override
        protected void authenticateInternal(CallbackHandler cbh) throws SmackJavaxSaslException {
            super.authenticateInternal(cbh);
            log.info("authenticateInternal " + cbh + " -> " + this.sc);
        }

        @Override
        protected byte[] getAuthenticationText() throws SmackJavaxSaslException {
            byte[] result = super.getAuthenticationText();
            log.info("getAuthenticationText -> " + (result == null ? result : Hex.encodeHexString(result)));
            return result;
        }
    }
}