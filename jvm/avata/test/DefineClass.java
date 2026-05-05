import java.io.IOException;
import java.io.File;
import java.io.FileInputStream;

public class DefineClass {
  private static File findClass(String name, File directory) {
    for (File file: directory.listFiles()) {
      if (file.isFile()) {
        if (file.getName().equals(name + ".class")) {
          return file;
        }
      } else if (file.isDirectory()) {
        File result = findClass(name, file);
        if (result != null) {
          return result;
        }
      }
    }
    return null;
  }

  private static byte[] read(File file) throws IOException {
    byte[] bytes = new byte[(int) file.length()];
    FileInputStream in = new FileInputStream(file);
    try {
      if (in.read(bytes) != (int) file.length()) {
        throw new RuntimeException();
      }
      return bytes;
    } finally {
      in.close();
    }
  }

  private static Class loadClass(String name) throws Exception {
    return new MyClassLoader(DefineClass.class.getClassLoader()).defineClass
      (name, read(findClass(name, new File(System.getProperty("user.dir")))));
  }

  private static void expect(boolean v) {
    if (! v) throw new RuntimeException();
  }

  private static void expectBounds(MyClassLoader loader,
                                   String name,
                                   byte[] bytes,
                                   int offset,
                                   int length)
  {
    try {
      loader.defineClass(name, bytes, offset, length);
      throw new RuntimeException("expected defineClass bounds exception");
    } catch (IndexOutOfBoundsException expected) {
    }
  }

  private static void testStatic() throws Exception {
    loadClass("DefineClass$Hello")
      .getMethod("main", String[].class).invoke(null, (Object) new String[0]);
  }

  private static void testDerived() throws Exception {
    System.out.println
      (String.valueOf
       (((Base) loadClass("DefineClass$Derived").newInstance()).zip()));
  }

  private static void testBounds() throws Exception {
    byte[] bytes = read(findClass("DefineClass$Padded", new File(System.getProperty("user.dir"))));
    byte[] padded = new byte[bytes.length + 1024];
    System.arraycopy(bytes, 0, padded, 512, bytes.length);

    Class paddedClass = new MyClassLoader(DefineClass.class.getClassLoader())
      .defineClass("DefineClass$Padded", padded, 512, bytes.length);
    expect(paddedClass.getName().equals("DefineClass$Padded"));

    MyClassLoader loader = new MyClassLoader(DefineClass.class.getClassLoader());
    expectBounds(loader, "DefineClass$Padded", bytes, -1, bytes.length);
    expectBounds(loader, "DefineClass$Padded", bytes, 0, -1);
    expectBounds(loader, "DefineClass$Padded", bytes, bytes.length + 1, 0);
    expectBounds(loader, "DefineClass$Padded", bytes, 1, bytes.length);
    expectBounds(loader, "DefineClass$Padded", bytes, Integer.MAX_VALUE, 1);
  }

  public static void main(String[] args) throws Exception {
    testStatic();
    testDerived();
    testBounds();
  }

  private static class MyClassLoader extends ClassLoader {
    public MyClassLoader(ClassLoader parent) {
      super(parent);
    }

    public Class defineClass(String name, byte[] bytes) {
      return defineClass(name, bytes, 0, bytes.length);
    }

    public Class defineClass(String name, byte[] bytes, int offset, int length) {
      return super.defineClass(name, bytes, offset, length);
    }
  }

  public static class Hello {
    public static void main(String[] args) {
      System.out.println("hello, world!");
    }
  }

  public abstract static class Base {
    public int foo;
    public int[] array;
    
    public void bar() { }

    public abstract int zip();
  }

  public static class Derived extends Base {
    public int zip() {
      return 42;
    }
  }

  public static class Padded {
  }
}
