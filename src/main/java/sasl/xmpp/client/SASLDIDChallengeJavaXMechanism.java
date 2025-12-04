package sasl.xmpp.client;

import demo.sasl.client.SaslClientCallbackHandler;
import demo.sasl.client.integration.UserIntegrationDemoDID;
import demo.sasl.client.integration.UserIntegrationInteractive;
import org.apache.commons.codec.binary.Hex;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jivesoftware.smack.sasl.SASLMechanism;
import org.jivesoftware.smack.sasl.javax.SASLJavaXMechanism;
import org.jivesoftware.smack.sasl.javax.SmackJavaxSaslException;
import sasl.mechanism.did.DIDChallengeSaslProvider;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import java.util.Map;

public class SASLDIDChallengeJavaXMechanism extends SASLJavaXMechanism {

    private static final Logger log = LogManager.getLogger(SASLDIDChallengeJavaXMechanism.class);

    private final boolean interactive;

    public SASLDIDChallengeJavaXMechanism(boolean interactive) {
        this.interactive = interactive;
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
    protected SASLMechanism newInstance() {
        return new SASLDIDChallengeJavaXMechanism(this.isInteractive());
    }

    @Override
    public boolean requiresPassword() {
        return false;
    }

    @Override
    protected void authenticateInternal() throws SmackJavaxSaslException {
        String[] mechanisms = {getName()};
        Map<String, String> props = getSaslProps();
        String authzid = null;
        if (authorizationId != null) {
            authzid = authorizationId.toString();
        }
        try {
            sc = Sasl.createSaslClient(mechanisms, authzid, "xmpp", getServerName().toString(), props,
                    new SaslClientCallbackHandler(this.isInteractive() ? new UserIntegrationInteractive() : new UserIntegrationDemoDID()));
        } catch (SaslException e) {
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

    public boolean isInteractive() {
        return this.interactive;
    }
}
