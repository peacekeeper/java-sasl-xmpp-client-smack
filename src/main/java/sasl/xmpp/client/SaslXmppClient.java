package sasl.xmpp.client;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jivesoftware.smack.AbstractXMPPConnection;
import org.jivesoftware.smack.chat2.Chat;
import org.jivesoftware.smack.chat2.ChatManager;
import org.jivesoftware.smack.chat2.IncomingChatMessageListener;
import org.jivesoftware.smack.packet.Message;
import org.jivesoftware.smack.tcp.XMPPTCPConnection;
import org.jivesoftware.smack.tcp.XMPPTCPConnectionConfiguration;
import org.jxmpp.jid.EntityBareJid;
import org.jxmpp.jid.impl.JidCreate;
import org.jxmpp.stringprep.XmppStringprepException;

import java.util.concurrent.TimeUnit;

public class SaslXmppClient {

    private static final Logger log = LogManager.getLogger(SaslXmppClient.class);

    private static final String DOMAIN_NAME = "java-sasl-xmpp-server";
    private static final String HOST = "java-sasl-xmpp-server";
    private static final String USERNAME_ALICE = "alice";
    private static final String USERNAME_BOB = "bob";
    private static final String PASSWORD_ALICE = "alicepass";
    private static final String PASSWORD_BOB = "bobpass";
    private static final EntityBareJid ENTITY_BARE_JID_ALICE;
    private static final EntityBareJid ENTITY_BARE_JID_BOB;

    static {
        try {
            ENTITY_BARE_JID_ALICE = JidCreate.entityBareFrom(USERNAME_ALICE + "@" + DOMAIN_NAME);
            ENTITY_BARE_JID_BOB = JidCreate.entityBareFrom(USERNAME_BOB + "@" + DOMAIN_NAME);
        } catch (XmppStringprepException ex) {
            throw new RuntimeException(ex.getMessage(), ex);
        }
    }

    public static void main(String[] args) throws Exception {

        // create configuration

        XMPPTCPConnectionConfiguration config = XMPPTCPConnectionConfiguration.builder()
                .setUsernameAndPassword(USERNAME_ALICE, PASSWORD_ALICE)
                .setXmppDomain(DOMAIN_NAME)
                .setHost(HOST)
                .build();
        log.debug("Created configuration: " + config);

        // establish a connection to the server and log in

        AbstractXMPPConnection connection = new XMPPTCPConnection(config);
        log.debug("Connection: " + connection);

        connection.connect();
        connection.login();
        log.debug("Logged in.");

        // chat

        ChatManager chatManager = ChatManager.getInstanceFor(connection);
        Chat chat = chatManager.chatWith(ENTITY_BARE_JID_BOB);
        log.debug("Created chat: " + chat);

        chat.send("Hello!");

        // add listener

        chatManager.addIncomingListener(new IncomingChatMessageListener() {
            @Override
            public void newIncomingMessage(EntityBareJid from, Message message, Chat chat) {
                System.out.println("New message from " + from + ": " + message.getBody());
            }
        });

        // loop

        while (connection.isConnected()) {
            Thread.sleep(TimeUnit.SECONDS.toMillis(10));
        }
    }
}