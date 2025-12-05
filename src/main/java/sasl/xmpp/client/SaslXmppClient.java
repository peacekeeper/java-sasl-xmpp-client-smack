package sasl.xmpp.client;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jivesoftware.smack.*;
import org.jivesoftware.smack.chat2.Chat;
import org.jivesoftware.smack.chat2.ChatManager;
import org.jivesoftware.smack.chat2.IncomingChatMessageListener;
import org.jivesoftware.smack.packet.*;
import org.jivesoftware.smack.sm.predicates.ForEveryMessage;
import org.jivesoftware.smack.sm.predicates.ForEveryStanza;
import org.jivesoftware.smack.tcp.XMPPTCPConnection;
import org.jivesoftware.smack.tcp.XMPPTCPConnectionConfiguration;
import org.jivesoftware.smack.util.Consumer;
import org.jivesoftware.smack.util.dns.dnsjava.DNSJavaResolver;
import org.jxmpp.jid.EntityBareJid;
import org.jxmpp.jid.impl.JidCreate;
import org.jxmpp.stringprep.XmppStringprepException;
import sasl.xmpp.client.ssl.TrustAllSSLSocketFactory;

import javax.security.auth.callback.UnsupportedCallbackException;
import java.util.concurrent.TimeUnit;

public abstract class SaslXmppClient implements ConnectionListener, StanzaListener {

    private static final Logger log = LogManager.getLogger(SaslXmppClient.class);

    private static final String DOMAIN_NAME = "java-sasl-xmpp-server";
    private static final String HOST = "localhost";
    private static final int PORT = 5222;
    private static final String USERNAME_BOB = "bob";
    private static final EntityBareJid ENTITY_BARE_JID_BOB;

    private final boolean interactive;

    static {
        try {
            ENTITY_BARE_JID_BOB = JidCreate.entityBareFrom(USERNAME_BOB + "@" + DOMAIN_NAME);
        } catch (XmppStringprepException ex) {
            throw new RuntimeException(ex.getMessage(), ex);
        }
    }

    protected abstract XMPPTCPConnectionConfiguration.Builder configureConnectionFactory(XMPPTCPConnectionConfiguration.Builder connectionConfigurationBuilder) throws UnsupportedCallbackException;

    protected SaslXmppClient(boolean interactive) {
        this.interactive = interactive;
    }

    public void run() throws Exception {

        // create configuration

        XMPPTCPConnectionConfiguration.Builder connectionConfigurationBuilder = XMPPTCPConnectionConfiguration.builder()
                .setXmppDomain(DOMAIN_NAME)
                .setHost(HOST)
                .setPort(PORT)
                .setSslContextFactory(new TrustAllSSLSocketFactory())
                .setCustomX509TrustManager(TrustAllSSLSocketFactory.createTrustManager())
                .setHostnameVerifier(TrustAllSSLSocketFactory.createHostnameVerifier());
        connectionConfigurationBuilder = this.configureConnectionFactory(connectionConfigurationBuilder);
        XMPPTCPConnectionConfiguration connectionConfiguration = connectionConfigurationBuilder.build();
        log.debug("Created configuration: " + connectionConfiguration);

        // setup DNS

        DNSJavaResolver.setup();
        log.debug("Setup DNSResolver");

        // establish a connection to the server and log in

        AbstractXMPPConnection connection = new XMPPTCPConnection(connectionConfiguration);
        connection.addConnectionListener(this);
        connection.addStanzaListener(this, ForEveryStanza.INSTANCE);
        log.debug("Connection: " + connection);

        connection.connect();
        log.debug("Connected? " + connection);

        connection.login();
        log.debug("Logged in? " + connection);
        log.debug("SASL mechanism: " + connection.getUsedSaslMechansism());

        // chat

        ChatManager chatManager = ChatManager.getInstanceFor(connection);
        Chat chat = chatManager.chatWith(ENTITY_BARE_JID_BOB);
        log.debug("Created chat: " + chat);

        // add listener

        chatManager.addIncomingListener(new IncomingChatMessageListener() {
            @Override
            public void newIncomingMessage(EntityBareJid from, Message message, Chat chat) {
                log.info("New message from " + from + ": " + message.getBody());
            }
        });

        // loop

        int i = 1;
        while (connection.isConnected()) {
            String message = "Hello! (" + i++ + ")";
            chat.send(message);
            log.debug("Sent message: " + message);
            Thread.sleep(TimeUnit.SECONDS.toMillis(5));
            log.info("Waiting.");
            Thread.sleep(TimeUnit.SECONDS.toMillis(5));
        }
    }

    @Override
    public void processStanza(Stanza packet) throws SmackException.NotConnectedException, InterruptedException, SmackException.NotLoggedInException {
        log.info("STANZA: " + packet);
        if (packet.getError() != null) {
            StanzaError stanzaError = packet.getError();
            log.error(stanzaError.toString());
        }
    }

    @Override
    public void connecting(XMPPConnection connection) {
        log.info("CONNECTING: " + connection);
    }

    @Override
    public void connected(XMPPConnection connection) {
        log.info("CONNECTED: " + connection);
    }

    @Override
    public void authenticated(XMPPConnection connection, boolean resumed) {
        log.info("AUTHENTICATED: " + connection + ", " + resumed);
    }

    @Override
    public void connectionClosed() {
        log.info("CONNECTION CLOSED");
    }

    @Override
    public void connectionClosedOnError(Exception e) {
        log.info("CONNECTION CLOSED ON ERROR: " + e.getMessage());
    }

    public boolean isInteractive() {
        return this.interactive;
    }
}