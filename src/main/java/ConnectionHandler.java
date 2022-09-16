import com.google.common.collect.ImmutableSet;
import org.apache.sshd.client.session.ClientSession;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.slf4j.Logger;

import java.io.FileReader;
import java.io.IOException;
import java.nio.channels.AsynchronousSocketChannel;
import java.security.*;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * Class uses to handle the incoming connections from CustomListener
 */
public class ConnectionHandler {


    private CustomSessionChannelConverter converter;
    private final Logger log = getLogger(ConnectionHandler.class);

    public ConnectionHandler(CustomSessionChannelConverter converter) {
        this.converter = converter;
    }


    /**
     * Parses an AsynchronousSocketChannel into a ClientSession object
     *
     * @param channel
     */
    public ClientSession convertConnectionChannelToSession(AsynchronousSocketChannel channel) {
        ClientSession session = null;
        try {
            log.info("Converting channel to client session...");
            session = converter.generateSessionFromChannel(channel);
        } catch (Exception e) {
            log.error("Exception converting Channel to Session: " + e);
        }
        return  session;
    }




    private static final String SSH_KEY = "/Users/macbookpro/.ssh/id_rsa";
    /**
     * Authenticates Client Session converted from Phone Home Listener
     * @param session
     * @param user
     * @return
     * @throws IOException
     */
    public boolean authenticateSessionSshKey(ClientSession session, String user) throws IOException {
        log.info("Authenticating Client Session...");
        try {
            session.setUsername(user);
            KeyPair keyPair = getSshKeyPair();
            session.addPublicKeyIdentity(keyPair);

            session.auth().verify(8, TimeUnit.SECONDS);

            Set<ClientSession.ClientSessionEvent> event = session.waitFor(
                    ImmutableSet.of(ClientSession.ClientSessionEvent.WAIT_AUTH,
                            ClientSession.ClientSessionEvent.CLOSED,
                            ClientSession.ClientSessionEvent.AUTHED), 0);

            if (!event.contains(ClientSession.ClientSessionEvent.AUTHED)) {
                System.out.println("Session closed {} {}" + event + session.isClosed());
                throw new IOException("Failed to authenticate session with device " + "check the user/pwd or key");
            }
            log.info("Session authenticated!");
            return true;

        } catch (IOException e) {
            log.error("Exception authenticating session: " + e);
            System.out.println("Exception authenticating session: " + e);
            throw e;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return false;
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            return false;
        }
    }


    private KeyPair getSshKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
        Security.addProvider(new BouncyCastleProvider());
        KeyFactory factory = KeyFactory.getInstance("RSA", "BC");

        try (PEMParser pemParser = new PEMParser(new FileReader(SSH_KEY))) {
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
            try {
                KeyPair kp = converter.getKeyPair((PEMKeyPair) pemParser.readObject());
                return kp;
            } catch (IOException e) {
                throw new IOException("Failed to authenticate session. Please check if ssk key is generated" + " : ", e);
            }
        }
    }




}
