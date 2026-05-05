public class Packages {
  private static void expect(boolean v) {
    if (! v) throw new RuntimeException();
  }

  private static class Loader extends ClassLoader {
    Package define(String name) {
      return definePackage(name, null, null, null, null, null, null, null);
    }

    Package lookup(String name) {
      return getPackage(name);
    }
  }

  public static void main(String[] args) {
    Loader loader = new Loader();
    Package p = loader.define("test.package");
    expect(loader.lookup("test.package") == p);
    expect(String.class.getPackage().getName().equals("java.lang"));
  }
}
