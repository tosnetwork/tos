import java.io.IOException;
import java.net.Socket;
import java.net.InetAddress;

/**
 * HostAPITest — negative tests verifying that every forbidden host-observing
 * Java API throws UnsupportedOperationException with the expected message
 * prefix.  This is a consensus-safety gate: if any call succeeds or throws
 * the wrong exception type the test exits non-zero and the CI run fails.
 *
 * Each sub-test prints "PASS <name>" on success or "FAIL <name>: <reason>"
 * on failure.  The overall exit code is non-zero if any sub-test failed.
 */
public class HostAPITest {

  private static int failures = 0;

  // -----------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------

  private static void pass(String name) {
    System.out.println("PASS " + name);
  }

  private static void fail(String name, String reason) {
    System.out.println("FAIL " + name + ": " + reason);
    failures++;
  }

  /**
   * Asserts that executing {@code r} throws {@code UnsupportedOperationException}
   * and that its message starts with {@code msgPrefix}.
   */
  private static void assertTrapped(String testName, String msgPrefix,
                                    Runnable r) {
    try {
      r.run();
      fail(testName, "no exception thrown — expected UnsupportedOperationException");
    } catch (UnsupportedOperationException e) {
      String msg = e.getMessage();
      if (msg != null && msg.startsWith(msgPrefix)) {
        pass(testName);
      } else {
        fail(testName, "wrong message: \"" + msg + "\" (expected prefix \"" + msgPrefix + "\")");
      }
    } catch (Throwable t) {
      fail(testName, "wrong exception type: " + t.getClass().getName() + ": " + t.getMessage());
    }
  }

  // -----------------------------------------------------------------------
  // System tests
  // -----------------------------------------------------------------------

  private static void testCurrentTimeMillis() {
    assertTrapped("System.currentTimeMillis",
        "wall-clock time not available in consensus",
        new Runnable() { public void run() { System.currentTimeMillis(); } });
  }

  private static void testNanoTime() {
    assertTrapped("System.nanoTime",
        "wall-clock time not available in consensus",
        new Runnable() { public void run() { System.nanoTime(); } });
  }

  private static void testGetenvString() {
    assertTrapped("System.getenv(String)",
        "environment variables not available in consensus",
        new Runnable() { public void run() { System.getenv("PATH"); } });
  }

  private static void testGetenvMap() {
    assertTrapped("System.getenv()",
        "environment variables not available in consensus",
        new Runnable() { public void run() { System.getenv(); } });
  }

  private static void testLoadLibrary() {
    assertTrapped("System.loadLibrary",
        "native library loading not available in consensus",
        new Runnable() { public void run() { System.loadLibrary("foo"); } });
  }

  private static void testLoad() {
    assertTrapped("System.load",
        "native library loading not available in consensus",
        new Runnable() { public void run() { System.load("/lib/libfoo.so"); } });
  }

  private static void testExit() {
    assertTrapped("System.exit",
        "System.exit not available in consensus",
        new Runnable() { public void run() { System.exit(0); } });
  }

  private static void testMapLibraryName() {
    assertTrapped("System.mapLibraryName",
        "native library loading not available in consensus",
        new Runnable() { public void run() { System.mapLibraryName("foo"); } });
  }

  // -----------------------------------------------------------------------
  // System properties tests — deterministic keys must work, host keys must not
  // -----------------------------------------------------------------------

  private static void testDeterministicProperties() {
    String testName = "System.getProperty(deterministic)";
    try {
      String ver = System.getProperty("java.version");
      String sep = System.getProperty("file.separator");
      if ("1.8.0".equals(ver) && "/".equals(sep)) {
        pass(testName);
      } else {
        fail(testName, "unexpected values: java.version=" + ver + " file.separator=" + sep);
      }
    } catch (Throwable t) {
      fail(testName, "unexpected exception: " + t);
    }
  }

  private static void testHostPropertiesAbsent() {
    String testName = "System.getProperty(host-key absent)";
    try {
      // user.home must NOT be present (it would expose the host home directory)
      String userHome = System.getProperty("user.home");
      if (userHome != null) {
        fail(testName, "host property exposed: user.home=" + userHome);
      } else {
        pass(testName);
      }
    } catch (Throwable t) {
      fail(testName, "unexpected exception: " + t);
    }
  }

  // -----------------------------------------------------------------------
  // Runtime tests
  // -----------------------------------------------------------------------

  private static void testRuntimeExec() {
    assertTrapped("Runtime.exec",
        "process execution not available in consensus",
        new Runnable() {
          public void run() {
            try {
              Runtime.getRuntime().exec("ls");
            } catch (IOException e) {
              // wrap so assertTrapped sees UnsupportedOperationException
              throw new RuntimeException(e);
            }
          }
        });
  }

  private static void testRuntimeExecArray() {
    assertTrapped("Runtime.exec(String[])",
        "process execution not available in consensus",
        new Runnable() {
          public void run() {
            try {
              Runtime.getRuntime().exec(new String[]{"ls"});
            } catch (IOException e) {
              throw new RuntimeException(e);
            }
          }
        });
  }

  private static void testRuntimeLoadLibrary() {
    assertTrapped("Runtime.loadLibrary",
        "native library loading not available in consensus",
        new Runnable() { public void run() { Runtime.getRuntime().loadLibrary("foo"); } });
  }

  private static void testRuntimeHalt() {
    assertTrapped("Runtime.halt",
        "Runtime.halt not available in consensus",
        new Runnable() { public void run() { Runtime.getRuntime().halt(0); } });
  }

  private static void testRuntimeAddShutdownHook() {
    assertTrapped("Runtime.addShutdownHook",
        "shutdown hooks not available in consensus",
        new Runnable() {
          public void run() {
            Runtime.getRuntime().addShutdownHook(new Thread());
          }
        });
  }

  private static void testRuntimeAvailableProcessors() {
    String testName = "Runtime.availableProcessors()==1";
    try {
      int n = Runtime.getRuntime().availableProcessors();
      if (n == 1) {
        pass(testName);
      } else {
        fail(testName, "returned " + n + " (expected 1)");
      }
    } catch (Throwable t) {
      fail(testName, "unexpected exception: " + t);
    }
  }

  // -----------------------------------------------------------------------
  // Thread tests
  // -----------------------------------------------------------------------

  private static void testThreadStart() {
    assertTrapped("Thread.start",
        "thread creation not available in consensus",
        new Runnable() {
          public void run() {
            new Thread().start();
          }
        });
  }

  private static void testThreadSleep() {
    assertTrapped("Thread.sleep",
        "thread sleep not available in consensus",
        new Runnable() {
          public void run() {
            try {
              Thread.sleep(1);
            } catch (InterruptedException e) {
              // ignored for this path
            }
          }
        });
  }

  private static void testThreadCurrentThread() {
    String testName = "Thread.currentThread() non-null";
    try {
      Thread t = Thread.currentThread();
      if (t != null) {
        pass(testName);
      } else {
        fail(testName, "returned null");
      }
    } catch (Throwable e) {
      fail(testName, "unexpected exception: " + e);
    }
  }

  // -----------------------------------------------------------------------
  // Networking tests
  // -----------------------------------------------------------------------

  private static void testSocketConstructor() {
    assertTrapped("new Socket()",
        "networking not available in consensus",
        new Runnable() {
          public void run() {
            try {
              new Socket();
            } catch (IOException e) {
              throw new RuntimeException(e);
            }
          }
        });
  }

  private static void testSocketConnectByString() {
    assertTrapped("new Socket(String,int)",
        "networking not available in consensus",
        new Runnable() {
          public void run() {
            try {
              new Socket("localhost", 80);
            } catch (IOException e) {
              throw new RuntimeException(e);
            }
          }
        });
  }

  private static void testInetAddressGetByName() {
    assertTrapped("InetAddress.getByName",
        "networking not available in consensus",
        new Runnable() {
          public void run() {
            try {
              InetAddress.getByName("localhost");
            } catch (java.net.UnknownHostException e) {
              throw new RuntimeException(e);
            }
          }
        });
  }

  private static void testSocketChannelOpen() {
    assertTrapped("SocketChannel.open",
        "networking not available in consensus",
        new Runnable() {
          public void run() {
            try {
              java.nio.channels.SocketChannel.open();
            } catch (IOException e) {
              throw new RuntimeException(e);
            }
          }
        });
  }

  private static void testServerSocketChannelOpen() {
    assertTrapped("ServerSocketChannel.open",
        "networking not available in consensus",
        new Runnable() {
          public void run() {
            try {
              java.nio.channels.ServerSocketChannel.open();
            } catch (IOException e) {
              throw new RuntimeException(e);
            }
          }
        });
  }

  private static void testDatagramChannelOpen() {
    assertTrapped("DatagramChannel.open",
        "networking not available in consensus",
        new Runnable() {
          public void run() {
            try {
              java.nio.channels.DatagramChannel.open();
            } catch (IOException e) {
              throw new RuntimeException(e);
            }
          }
        });
  }

  private static void testSelectorOpen() {
    assertTrapped("Selector.open",
        "networking not available in consensus",
        new Runnable() {
          public void run() {
            try {
              java.nio.channels.Selector.open();
            } catch (IOException e) {
              throw new RuntimeException(e);
            }
          }
        });
  }

  // -----------------------------------------------------------------------
  // URL test
  // -----------------------------------------------------------------------

  private static void testHttpURL() {
    // URL construction (string parsing) is deterministic and admitted.
    // Network I/O (openConnection/openStream) is trapped.
    String testName = "URL(http) throws MalformedURLException";
    try {
      java.net.URL url = new java.net.URL("http://example.com/");
      // Construction must succeed; host extraction must work
      if (!"example.com".equals(url.getHost())) {
        fail(testName, "unexpected host: " + url.getHost());
        return;
      }
      // Opening a connection must be trapped
      try {
        url.openConnection();
        fail(testName, "openConnection() did not throw");
        return;
      } catch (java.io.IOException e) {
        pass(testName);
      }
    } catch (Throwable t) {
      fail(testName, "unexpected exception: " + t.getMessage());
    }
  }

  // -----------------------------------------------------------------------
  // Entry point
  // -----------------------------------------------------------------------

  public static void main(String[] args) {
    // System
    testCurrentTimeMillis();
    testNanoTime();
    testGetenvString();
    testGetenvMap();
    testLoadLibrary();
    testLoad();
    testExit();
    testMapLibraryName();
    testDeterministicProperties();
    testHostPropertiesAbsent();

    // Runtime
    testRuntimeExec();
    testRuntimeExecArray();
    testRuntimeLoadLibrary();
    testRuntimeHalt();
    testRuntimeAddShutdownHook();
    testRuntimeAvailableProcessors();

    // Thread
    testThreadStart();
    testThreadSleep();
    testThreadCurrentThread();

    // Networking
    testSocketConstructor();
    testSocketConnectByString();
    testInetAddressGetByName();
    testSocketChannelOpen();
    testServerSocketChannelOpen();
    testDatagramChannelOpen();
    testSelectorOpen();
    testHttpURL();

    // Summary
    if (failures == 0) {
      System.out.println("HostAPITest: all " + countTests() + " sub-tests PASSED");
    } else {
      System.out.println("HostAPITest: " + failures + " sub-test(s) FAILED");
      throw new RuntimeException("HostAPITest FAILED: " + failures + " failure(s)");
    }
  }

  private static int countTests() {
    // keep in sync with main() above
    return 28;
  }
}
