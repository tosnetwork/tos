import java.internal.Classes;
import java.internal.SystemClassSpace;
import java.internal.VMClass;
import java.internal.VMMethod;
import avata.testing.bytecode.Assembler;
import avata.testing.bytecode.ConstantPool;
import avata.testing.bytecode.ConstantPool.PoolEntry;
import avata.testing.bytecode.Stream;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class StackTraceSourceFileTest {
  private static final int ATHROW = 0xbf;
  private static final String GENERATED = "StackTraceSourceFileTest$Generated";
  private static final String HOST_PATH = "/tmp/validator/private/SecretContract.java";
  private static final String SANITIZED = "SecretContract.java";
  private static final String WINDOWS_HOST_PATH = "C:\\Users\\validator\\contracts\\Foo.java";
  private static final String WINDOWS_SANITIZED = "Foo.java";
  private static final String PLAIN_FILENAME = "Simple.java";

  private static VMClass defineVM(String name, byte[] bytes) {
    return Classes.defineVMClass(
        SystemClassSpace.appClassSpace(), bytes, 0, bytes.length);
  }

  private static byte[] throwRuntimeExceptionCode(int exceptionClass,
                                                  int constructor)
      throws IOException {
    ByteArrayOutputStream instructions = new ByteArrayOutputStream();
    Stream.write1(instructions, Assembler.new_);
    Stream.write2(instructions, exceptionClass + 1);
    Stream.write1(instructions, Assembler.dup);
    Stream.write1(instructions, Assembler.invokespecial);
    Stream.write2(instructions, constructor + 1);
    Stream.write1(instructions, ATHROW);

    byte[] body = instructions.toByteArray();
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    Stream.write2(out, 2); // max stack
    Stream.write2(out, 0); // max locals
    Stream.write4(out, body.length);
    out.write(body);
    Stream.write2(out, 0); // exception handler table length
    Stream.write2(out, 0); // code attribute count
    return out.toByteArray();
  }

  private static byte[] makeGeneratedClass(String sourceFilePath) throws IOException {
    List<PoolEntry> pool = new ArrayList<PoolEntry>();
    int className = ConstantPool.addClass(pool, GENERATED);
    int superName = ConstantPool.addClass(pool, "java/lang/Object");
    int codeName = ConstantPool.addUtf8(pool, "Code");
    int sourceFileName = ConstantPool.addUtf8(pool, "SourceFile");
    int sourceFileValue = ConstantPool.addUtf8(pool, sourceFilePath);
    int methodName = ConstantPool.addUtf8(pool, "boom");
    int methodSpec = ConstantPool.addUtf8(pool, "()V");
    int exceptionClass = ConstantPool.addClass(pool, "java/lang/RuntimeException");
    int constructor = ConstantPool.addMethodRef(
        pool, "java/lang/RuntimeException", "<init>", "()V");
    byte[] code = throwRuntimeExceptionCode(exceptionClass, constructor);

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    Stream.write4(out, 0xCAFEBABE);
    Stream.write2(out, 0); // minor version
    Stream.write2(out, 50); // major version
    Stream.write2(out, pool.size() + 1);
    for (PoolEntry e : pool) {
      e.writeTo(out);
    }
    Stream.write2(out, Assembler.ACC_PUBLIC);
    Stream.write2(out, className + 1);
    Stream.write2(out, superName + 1);
    Stream.write2(out, 0); // interfaces
    Stream.write2(out, 0); // fields
    Stream.write2(out, 1); // methods
    Stream.write2(out, Assembler.ACC_PUBLIC | Assembler.ACC_STATIC);
    Stream.write2(out, methodName + 1);
    Stream.write2(out, methodSpec + 1);
    Stream.write2(out, 1); // method attributes
    Stream.write2(out, codeName + 1);
    Stream.write4(out, code.length);
    out.write(code);
    Stream.write2(out, 1); // class attributes
    Stream.write2(out, sourceFileName + 1);
    Stream.write4(out, 2);
    Stream.write2(out, sourceFileValue + 1);
    return out.toByteArray();
  }

  private static byte[] makeGeneratedClass() throws IOException {
    return makeGeneratedClass(HOST_PATH);
  }

  private static byte[] makeClassWithoutSourceFile() throws IOException {
    List<PoolEntry> pool = new ArrayList<PoolEntry>();
    int className = ConstantPool.addClass(pool, GENERATED);
    int superName = ConstantPool.addClass(pool, "java/lang/Object");
    int codeName = ConstantPool.addUtf8(pool, "Code");
    int methodName = ConstantPool.addUtf8(pool, "boom");
    int methodSpec = ConstantPool.addUtf8(pool, "()V");
    int exceptionClass = ConstantPool.addClass(pool, "java/lang/RuntimeException");
    int constructor = ConstantPool.addMethodRef(
        pool, "java/lang/RuntimeException", "<init>", "()V");
    byte[] code = throwRuntimeExceptionCode(exceptionClass, constructor);

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    Stream.write4(out, 0xCAFEBABE);
    Stream.write2(out, 0); // minor version
    Stream.write2(out, 50); // major version
    Stream.write2(out, pool.size() + 1);
    for (PoolEntry e : pool) {
      e.writeTo(out);
    }
    Stream.write2(out, Assembler.ACC_PUBLIC);
    Stream.write2(out, className + 1);
    Stream.write2(out, superName + 1);
    Stream.write2(out, 0); // interfaces
    Stream.write2(out, 0); // fields
    Stream.write2(out, 1); // methods
    Stream.write2(out, Assembler.ACC_PUBLIC | Assembler.ACC_STATIC);
    Stream.write2(out, methodName + 1);
    Stream.write2(out, methodSpec + 1);
    Stream.write2(out, 1); // method attributes
    Stream.write2(out, codeName + 1);
    Stream.write4(out, code.length);
    out.write(code);
    Stream.write2(out, 0); // no class attributes
    return out.toByteArray();
  }

  private static String findFileName(StackTraceElement[] trace) {
    for (int i = 0; i < trace.length; ++i) {
      if (GENERATED.equals(trace[i].getClassName())
          && "boom".equals(trace[i].getMethodName())) {
        return trace[i].getFileName();
      }
    }
    return "FRAME_MISSING";
  }

  private static void check(boolean condition, String message) {
    if (!condition) {
      throw new RuntimeException(message);
    }
  }

  public static void main(String[] args) throws Exception {
    // Case 1: Unix-style absolute path must be stripped to basename.
    {
      VMClass class_ = defineVM(GENERATED, makeGeneratedClass());
      VMMethod method = Classes.findMethod(class_, "boom", "()V");
      check(method != null, "generated method missing");

      try {
        Classes.invokeVMMethod(method, null, new Object[0]);
      } catch (RuntimeException expected) {
        String file = findFileName(expected.getStackTrace());
        check(SANITIZED.equals(file), "unix path: unsanitized SourceFile: " + file);
        check(file.indexOf('/') < 0 && file.indexOf('\\') < 0,
              "unix path: SourceFile contains a path separator");
      }
    }

    // Case 2: Windows-style path with backslash separators must be stripped.
    {
      VMClass class_ = defineVM(GENERATED, makeGeneratedClass(WINDOWS_HOST_PATH));
      VMMethod method = Classes.findMethod(class_, "boom", "()V");
      check(method != null, "windows class method missing");

      try {
        Classes.invokeVMMethod(method, null, new Object[0]);
      } catch (RuntimeException expected) {
        String file = findFileName(expected.getStackTrace());
        check(WINDOWS_SANITIZED.equals(file),
              "windows path: unsanitized SourceFile: " + file);
        check(file.indexOf('/') < 0 && file.indexOf('\\') < 0,
              "windows path: SourceFile contains a path separator");
      }
    }

    // Case 3: A plain filename with no separators must pass through unchanged.
    {
      VMClass class_ = defineVM(GENERATED, makeGeneratedClass(PLAIN_FILENAME));
      VMMethod method = Classes.findMethod(class_, "boom", "()V");
      check(method != null, "plain class method missing");

      try {
        Classes.invokeVMMethod(method, null, new Object[0]);
      } catch (RuntimeException expected) {
        String file = findFileName(expected.getStackTrace());
        check(PLAIN_FILENAME.equals(file),
              "plain filename: unexpected SourceFile: " + file);
      }
    }

    // Case 4: No SourceFile attribute — fileName must be null, not an error.
    {
      VMClass class_ = defineVM(GENERATED, makeClassWithoutSourceFile());
      VMMethod method = Classes.findMethod(class_, "boom", "()V");
      check(method != null, "no-sourcefile class method missing");

      try {
        Classes.invokeVMMethod(method, null, new Object[0]);
      } catch (RuntimeException expected) {
        String file = findFileName(expected.getStackTrace());
        check(file == null, "no SourceFile: expected null fileName, got: " + file);
      }
    }

    System.out.println("StackTraceSourceFileTest: all passed");
  }
}
