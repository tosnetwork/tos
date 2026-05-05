import java.net.SocketAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.channels.SocketChannel;
import java.nio.ByteBuffer;
import java.io.IOException;

public class Sockets {
  private static void expect(boolean v) {
    if (! v) throw new RuntimeException();
  }

  public static void testFailedBind() throws Exception {
    final String Hostname = "localhost";
    final int Port = 22046; // hopefully this port is unused
    final SocketAddress Address = new InetSocketAddress(Hostname, Port);
    final byte[] Message = "hello, world!".getBytes();

    SocketChannel out = SocketChannel.open();
    try {
      try {
        out.connect(Address);
        expect(false);
      } catch(IOException e) {
        // We're good.  This previously triggered a vm assert, rather than an exception
      }
    } finally {
      out.close();
    }
  }

  public static void main(String[] args) throws Exception {
    Socket socket = new Socket();
    socket.close();
    socket.close();

    SocketChannel channel = SocketChannel.open();
    Socket handle = channel.socket();
    handle.close();
    channel.close();

    try {
      channel.write(new ByteBuffer[1], 1, Integer.MAX_VALUE);
      expect(false);
    } catch (IndexOutOfBoundsException expected) {
    }

    // This test sometimes fails without explanation on Travis-CI, so
    // we skip it there:
    if (! "true".equals(System.getenv("TRAVIS"))) {
      testFailedBind();
    }
  }
}
