package sharerequests;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.Date;

/**
 * This is a bare minimum http server used to "catch" shared requests and
 * sinkhole them. Shared urls use a custom handler (http://burpsharedrequest)
 * that obviously isn't a routable address which causes issues with Burp. To
 * handle this, when the requests are parsed the traffic is sent here to
 * reply with a mock answer.
 */
public class CustomURLServer implements Runnable {

    private static final String NEW_LINE = "\r\n";
    private final SharedValues sharedValues;

    private final ServerSocket socket;
    private boolean running;

    public CustomURLServer(SharedValues sharedValues) throws IOException {
        this.sharedValues = sharedValues;
        socket = new ServerSocket(0);
    }

    @Override
    public void run() {
        running = true;
        try {
            while (running) {
                handleConnection(socket.accept());
            }
        } catch (SocketException tr) {
            sharedValues.getCallbacks().printError("Inner Server Closed.");
        } catch (IOException io) {
            sharedValues.getCallbacks().printError("Exception in socket: " + io);
        }

    }

    /**
     * This web server replies with "Link Processed!" to every request
     */
    private void handleConnection(Socket connection) {
        try {
            OutputStream out = new BufferedOutputStream(connection.getOutputStream());
            PrintStream pout = new PrintStream(out);

            String response = "Link Processed!";

            pout.print(
                    "HTTP/1.0 200 OK" + NEW_LINE +
                            "Content-Type: text/plain" + NEW_LINE +
                            "Date: " + new Date() + NEW_LINE +
                            "Content-length: " + response.length() + NEW_LINE + NEW_LINE +
                            response
            );

            pout.close();
        } catch (Exception tri) {
            sharedValues.getCallbacks().printError(tri.getMessage());
        }
    }


    ServerSocket getSocket() {
        return socket;
    }

    void stopRunning() {
        running = false;
        try {
            this.socket.close();
        } catch (IOException e) {
            sharedValues.getCallbacks().printError("Error closing socket");
        }
    }
}
