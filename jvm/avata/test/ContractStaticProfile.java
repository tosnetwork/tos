public class ContractStaticProfile {
  private static int counter;
  private static String value = "ready";

  public static void writePrimitive() {
    counter = 7;
  }

  public static int readPrimitive() {
    return counter;
  }

  public static void writeObject() {
    value = "changed";
  }

  public static String readObject() {
    return value;
  }

  public static void main(String[] args) {
    writePrimitive();
    if (readPrimitive() != 7) {
      throw new RuntimeException("static primitive write failed");
    }

    writeObject();
    if (!"changed".equals(readObject())) {
      throw new RuntimeException("static object write failed");
    }
  }
}
