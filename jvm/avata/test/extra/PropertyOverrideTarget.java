package extra;

public class PropertyOverrideTarget {
  private static void expect(boolean v) {
    if (! v) throw new RuntimeException();
  }

  public static void main(String[] args) {
    expect(args.length == 2);
    expect(args[1].equals(System.getProperty(args[0])));
  }
}
