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

  private static byte[] makeGeneratedClass() throws IOException {
    List<PoolEntry> pool = new ArrayList<PoolEntry>();
    int className = ConstantPool.addClass(pool, GENERATED);
    int superName = ConstantPool.addClass(pool, "java/lang/Object");
    int codeName = ConstantPool.addUtf8(pool, "Code");
    int sourceFileName = ConstantPool.addUtf8(pool, "SourceFile");
    int sourceFileValue = ConstantPool.addUtf8(pool, HOST_PATH);
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

  private static void check(boolean condition, String message) {
    if (!condition) {
      throw new RuntimeException(message);
    }
  }

  public static void main(String[] args) throws Exception {
    VMClass class_ = defineVM(GENERATED, makeGeneratedClass());
    VMMethod method = Classes.findMethod(class_, "boom", "()V");
    check(method != null, "generated method missing");

    try {
      Classes.invokeVMMethod(method, null, new Object[0]);
    } catch (RuntimeException expected) {
      StackTraceElement[] trace = expected.getStackTrace();
      for (int i = 0; i < trace.length; ++i) {
        StackTraceElement e = trace[i];
        if (GENERATED.equals(e.getClassName())
            && "boom".equals(e.getMethodName())) {
          String file = e.getFileName();
          check(SANITIZED.equals(file), "unsanitized SourceFile: " + file);
          check(file.indexOf('/') < 0 && file.indexOf('\\') < 0,
                "SourceFile contains a path separator");
          System.out.println("StackTraceSourceFileTest: all passed");
          return;
        }
      }
      throw new RuntimeException("generated frame missing");
    }

    throw new RuntimeException("expected generated exception");
  }
}
