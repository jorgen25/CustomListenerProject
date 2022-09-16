import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.keyverifier.DefaultKnownHostsServerKeyVerifier;
import org.apache.sshd.client.keyverifier.KnownHostsServerKeyVerifier;
import org.apache.sshd.client.keyverifier.ServerKeyVerifier;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.io.AbstractIoServiceFactory;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.slf4j.Logger;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.channels.AsynchronousChannelGroup;
import java.nio.channels.AsynchronousServerSocketChannel;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.security.PublicKey;
import java.util.concurrent.ExecutorService;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * Opens up listener on 4334 PORT
 * NOTE: We are currently using a modified apache.sshd.Nio2Connector to generate the Client Session (CustomSessionChannelConverter class).
 * Nio2Connector original implementation REQUIRES the channel used to generate that Session to be an AsynchronousChannel. Which is the
 * reason we needed to implement our own listener in this class with an AsynchronousServerSocketChannel serverChannel
 */
public class CustomListener {

    private static final int PORT = 4334;
    private static final String USERNAME = "user";
    private static final String PASSWORD = "password";
    private AsynchronousServerSocketChannel serverChannel;
    private CustomSessionChannelConverter converter;
    private com.cleancode.forstack.ConnectionHandler connection;
    private SshClient factoryManager;
    private InetSocketAddress hostAddress = new InetSocketAddress(PORT);
    private final Logger log = getLogger(CustomListener.class);


    public CustomListener() throws IOException {
        factoryManager = SshClient.setUpDefaultClient();
//        factoryManager.setKeyPairProvider(new SimpleGeneratorHostKeyProvider());

        KnownHostsServerKeyVerifier verifier = new DefaultKnownHostsServerKeyVerifier(new ServerKeyVerifier() {
            @Override
            public boolean verifyServerKey(ClientSession clientSession, SocketAddress remoteAddress, PublicKey serverKey) {

                //My goal is to check the public key here , but it never gets called
                return false;
            }
        }, false);

        factoryManager.setServerKeyVerifier(verifier);
        factoryManager.start();

        ExecutorService executorService = ((AbstractIoServiceFactory) (factoryManager.getIoServiceFactory())).getExecutorService();
        AsynchronousChannelGroup group = AsynchronousChannelGroup.withThreadPool(ThreadUtils.protectExecutorServiceShutdown(executorService, true));
        converter = new CustomSessionChannelConverter(factoryManager, factoryManager.getSessionFactory(), group);
        connection = new com.cleancode.forstack.ConnectionHandler(converter);
    }


    /**
     * Stops listening for incoming connections
     *
     * @throws IOException
     */
    public void stop() throws IOException {
        serverChannel.close();
    }

    /**
     * Starts listening for incoming connections on specified Port
     */
    public void start() throws IOException {
        serverChannel = AsynchronousServerSocketChannel.open();
        serverChannel.bind(hostAddress);

        serverChannel.accept(null, new CompletionHandler<AsynchronousSocketChannel, Object>() {

            @Override
            public void completed(AsynchronousSocketChannel result, Object attachment) {
                log.info("Heard connection: " + result);
                serverChannel.accept(null, this);
                AsynchronousSocketChannel clientChannel = result;
                handleIncomingConnection(clientChannel);
            }

            @Override
            public void failed(Throwable ex, Object attachment) {
                log.error("There was an error listening to connections: " + ex);
                serverChannel.accept(null, this);
            }
        });
    }

    /**
     * Method used to handle received connections from the listener in order to convert connection into a
     * ClientSession object that can be authenticated
     * @param channel
     */

    private void handleIncomingConnection(AsynchronousSocketChannel channel) {
        if (channel.isOpen()) {
            ClientSession session = convertConnectionChannelToSession(channel);
            if (session != null) {
                try {
                    boolean authenticated = authenticateSessionWithKey(session);
                    System.out.println(authenticated);
                } catch(Exception ex) {
                    log.error("Could not authenticate session from incoming connection: " + ex);
                }
            }
        }
    }

    /**
     * Receives the asynchronous channel object from incoming  calls and uses the
     * ConnectionHandler class to parse it into a clientSession
     *
     * @param channel
     */
    private ClientSession convertConnectionChannelToSession(AsynchronousSocketChannel channel) {
        ClientSession session = connection.convertConnectionChannelToSession(channel);
        return session;
    }

    /**
     * Uses the connectionHandler to authenticate the session with sshKey
     *
     * @param session
     * @return
     * @throws Exception
     */
    private boolean authenticateSessionWithKey(ClientSession session) throws IOException {
        boolean val = connection.authenticateSessionSshKey(session, USERNAME);
        return val;
    }


}
