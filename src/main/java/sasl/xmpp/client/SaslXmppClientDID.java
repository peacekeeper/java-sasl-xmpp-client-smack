package sasl.xmpp.client;

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

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import java.security.Security;

public class SaslXmppClientDID extends SaslXmppClient {

    private static final Logger log = LogManager.getLogger(SaslXmppClientDID.class);

    private static final String DID = "did:key:z6MkfePUhxLV6cM54cgZ4bGmnEdTNm3WDf4arwh5kR3dH51D";
    private static final String PRIVATEKEY = """
            {
                "kid": "did:key:z6MkfePUhxLV6cM54cgZ4bGmnEdTNm3WDf4arwh5kR3dH51D#z6MkfePUhxLV6cM54cgZ4bGmnEdTNm3WDf4arwh5kR3dH51D",
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "EbV6-hVmDiD3DKTUgsf2SjjnO7t0ttwMhStQ5JyCFhw",
                "d": "vGjHIZzZxS3R4mo-V0I_S72ULXDqa2INqkAtuvqJUN8"
            }
            """;

    static {
        Security.addProvider(new DIDChallengeSaslProvider());
    }

    static {
        SaslClientDebug.logSaslClientFactoriesAndMechanisms();
    }

    static {
        log.debug("SASL mechanisms: " + SASLAuthentication.getRegisterdSASLMechanisms());
        SASLAuthentication.registerSASLMechanism(new SASLDIDChallengeJavaXMechanism());
    }

    @Override
    protected XMPPTCPConnectionConfiguration.Builder configureConnectionFactory(XMPPTCPConnectionConfiguration.Builder connectionConfigurationBuilder) {
        return connectionConfigurationBuilder
                .setUsernameAndPassword(DID, null)
                .addEnabledSaslMechanism("DID-CHALLENGE");
    }

    @Override
    public void run() throws Exception {
        super.run();
    }

    public static void main(String[] args) throws Exception {
        new SaslXmppClientDID().run();
    }

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
            super.authenticateInternal();
            log.info("authenticateInternal -> " + this.sc);
        }

        @Override
        protected void authenticateInternal(CallbackHandler cbh) throws SmackJavaxSaslException {
            super.authenticateInternal(cbh);
            log.info("authenticateInternal " + cbh + " -> " + this.sc);
        }

        @Override
        protected byte[] getAuthenticationText() throws SmackJavaxSaslException {
            byte[] result = super.getAuthenticationText();
            log.info("getAuthenticationText -> " + Hex.encodeHexString(result));
            return result;
        }
    }

    private static class SASLDIDChallengeMechanism extends SASLMechanism {

        private final SaslClient saslClient;

        private SASLDIDChallengeMechanism() {
            try {
                this.saslClient = new DIDChallengeSaslClient(null, null);
            } catch (SaslException ex) {
                throw new RuntimeException(ex.getMessage(), ex);
            }
        }

        @Override
        protected void authenticateInternal(CallbackHandler cbh) throws SmackException.SmackSaslException {
            throw new UnsupportedOperationException("Not supported");
        }

        @Override
        protected byte[] getAuthenticationText() throws SmackException.SmackSaslException {
            throw new UnsupportedOperationException("Not supported");
        }

        @Override
        public String getName() {
            return DIDChallengeSaslProvider.MECHANISM_NAME;
        }

        @Override
        public int getPriority() {
            return 0;
        }

        @Override
        protected void checkIfSuccessfulOrThrow() throws SmackException.SmackSaslException {
            if (!this.saslClient.isComplete()) {
                throw new SmackException.SmackSaslException(this.getName() + " was not completed");
            }
        }

        @Override
        protected SASLMechanism newInstance() {
            return new SASLDIDChallengeMechanism();
        }
    }
}