import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.io.nio2.Nio2Connector;
import org.apache.sshd.common.io.nio2.Nio2Session;
import org.apache.sshd.common.util.GenericUtils;

import java.io.IOException;
import java.nio.channels.AsynchronousChannelGroup;
import java.nio.channels.AsynchronousSocketChannel;


/**
 * Class is a modification of Nio2Connector class. We use SessionChannelConverter to convert an incoming
 * connection from our CustomListener into a ClientSession that can be authenticated
 */
public class CustomSessionChannelConverter extends Nio2Connector {

    /**
     * When the Nio2 Session is created from the channel, the ClientSession is attached to the
     * newly created session-s attributes with this key
     */
    private static final String CLIENT_SESSION_ATTR_KEY = "org.apache.sshd.session";

    public CustomSessionChannelConverter(FactoryManager manager, IoHandler handler, AsynchronousChannelGroup group) {
        super(manager, handler, group);
    }


    /**
     * Method created to parse the async channel we get from the incoming tcp connection into a nio2Session, which also
     * generates a ClientSession
     * @param channel - Async channel from listener incoming connections
     * @return clientSessionImpl object
     */
    public ClientSession generateSessionFromChannel(final AsynchronousSocketChannel channel) {
        AsynchronousSocketChannel socket = null;
        ClientSession clientSession = null;
        try {
            socket = (AsynchronousSocketChannel)this.setSocketOptions(channel);
            clientSession = generateSession(socket, super.getFactoryManager(), super.getIoHandler());
        } catch (Throwable exc) {
            Throwable t = GenericUtils.peelException(exc);
            if (this.log.isDebugEnabled()) {
                this.log.debug("failed ({}) to schedule connection: {}", new Object[]{t.getClass().getSimpleName(), t.getMessage()});
            }

            if (this.log.isTraceEnabled()) {
                this.log.trace("connect(" + channel + ") connection failure details", t);
            }

            try {
                if (channel != null) {
                    channel.close();
                }
            } catch (IOException err) {
                if (this.log.isDebugEnabled()) {
                    this.log.debug("failed ({}) to close channel: {}", new Object[]{err.getClass().getSimpleName(), err.getMessage()});
                }
            }
        }
        return clientSession;
    }


    /**
     * Method is a copy of the completion handler in Nio2Connector, did not want to make any major changes to how the
     * session object is created
     * @param socket Asynchronous channel from the listener incoming connections
     * @param manager SShClient object
     * @param handler SshClient.getSessionFactory
     * @return ClientSessionImpl object
     */
    private ClientSession generateSession(final AsynchronousSocketChannel socket, final FactoryManager manager, final IoHandler handler) {
        Long sessionId = null;
        ClientSession clientSession = null;
        try {
            Nio2Session session = createSession(manager, handler, socket);
            handler.sessionCreated(session);
            sessionId = session.getId();
            this.sessions.put(sessionId, session);

            if (session.isClosing()) {
                try {
                    handler.sessionClosed(session);
                } finally {
                    this.unmapSession(sessionId);
                }
            } else {
                session.startReading();
            }

            //Client Session is here
            clientSession = (ClientSession) session.getAttribute(CLIENT_SESSION_ATTR_KEY);
        } catch (Throwable exc) {
            Throwable t = GenericUtils.peelException(exc);
            if (CustomSessionChannelConverter.this.log.isDebugEnabled()) {
                CustomSessionChannelConverter.this.log.debug("onCompleted - failed {} to start session: {}", t.getClass().getSimpleName(), t.getMessage());
            }

            if (CustomSessionChannelConverter.this.log.isTraceEnabled()) {
                CustomSessionChannelConverter.this.log.trace("onCompleted - session creation failure details", t);
            }

            try {
                socket.close();
            } catch (IOException ex) {
                if (CustomSessionChannelConverter.this.log.isDebugEnabled()) {
                    CustomSessionChannelConverter.this.log.debug("onCompleted - failed {} to close socket: {}", ex.getClass().getSimpleName(), ex.getMessage());
                }
            }
            CustomSessionChannelConverter.this.unmapSession(sessionId);
        }
        return clientSession;
    }


    /**
     * Original method from Nio2Connector class
     * @param manager
     * @param handler
     * @param socket
     * @return
     * @throws Throwable
     */
    protected Nio2Session createSession(FactoryManager manager, IoHandler handler, AsynchronousSocketChannel socket) throws Throwable {
        return new Nio2Session(this, manager, handler, socket);
    }

}
