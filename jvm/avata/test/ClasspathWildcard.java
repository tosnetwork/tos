import java.io.File;
import java.io.IOException;
import java.io.InputStream;

public class ClasspathWildcard {
  private static class Result {
    final int code;
    final String out;
    final String err;

    Result(Process process) throws IOException, InterruptedException {
      code = process.waitFor();
      out = read(process.getInputStream());
      err = read(process.getErrorStream());
    }
  }

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

  private static Result run(String[] command)
    throws IOException, InterruptedException
  {
    return new Result(Runtime.getRuntime().exec(command));
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

    Result result = run(command);

    expect(result.code == 0);
    expect(result.out.length() == 0);
    expect(result.err.length() == 0);

    String[] propertyCommand = {
      new File(buildDir, executableName).getPath(),
      "-Dfile.encoding=ISO-8859-1",
      "-cp",
      classpath,
      "extra.PropertyOverrideTarget",
      "file.encoding",
      "ISO-8859-1"
    };

    result = run(propertyCommand);

    expect(result.code == 0);
    expect(result.out.length() == 0);
    expect(result.err.length() == 0);
  }
}
