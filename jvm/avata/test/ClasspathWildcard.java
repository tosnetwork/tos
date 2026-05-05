import java.io.File;
import java.io.IOException;
import java.io.InputStream;

public class ClasspathWildcard {
  private static void expect(boolean v) {
    if (! v) throw new RuntimeException();
  }

  private static String read(InputStream in) throws IOException {
    StringBuilder builder = new StringBuilder();
    for (int c = in.read(); c != -1; c = in.read()) {
      builder.append((char) c);
    }
    return builder.toString();
  }

  public static void main(String[] args) throws Exception {
    if (System.getProperty("avata.version") == null) {
      return;
    }

    String classpath = System.getProperty("java.class.path");
    int separator = classpath.indexOf(File.pathSeparatorChar);
    File testDir = new File(separator == -1
                            ? classpath
                            : classpath.substring(0, separator))
      .getAbsoluteFile();
    File buildDir = testDir.getParentFile();

    String executableName = System.getProperty("os.name").equals("Windows")
      ? "avata.exe"
      : "avata";

    String[] command = {
      new File(buildDir, executableName).getPath(),
      "-cp",
      new File(buildDir, "wildcard-lib").getPath() + File.separator + "*",
      "extra.ClasspathWildcardTarget"
    };

    Process process = Runtime.getRuntime().exec(command);
    int code = process.waitFor();
    String out = read(process.getInputStream());
    String err = read(process.getErrorStream());

    expect(code == 0);
    expect(out.length() == 0);
    expect(err.length() == 0);
  }
}
