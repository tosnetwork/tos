import java.internal.Classes;
import java.internal.SystemClassSpace;
import java.internal.VMClass;
import java.internal.VMMethod;
import avata.testing.bytecode.Assembler;
import avata.testing.bytecode.Assembler.FieldData;
import avata.testing.bytecode.Assembler.MethodData;
import avata.testing.bytecode.ConstantPool;
import avata.testing.bytecode.ConstantPool.PoolEntry;
import avata.testing.bytecode.Stream;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

public class VerifierProfile {
  private static int constantMethodHandle() { return 15; }
  private static int constantMethodType() { return 16; }
  private static int constantInvokeDynamic() { return 18; }
  private static int refInvokeStatic() { return 6; }
  private static int accProtected() { return 0x0004; }
  private static int accFinal() { return 0x0010; }
  private static int accSynchronized() { return 0x0020; }
  private static int accNative() { return 0x0100; }
  private static int accAbstract() { return 0x0400; }
  private static int accEnum() { return 0x4000; }
  private static int opcodeGetstatic() { return 0xb2; }

  private interface Thrower {
    void run() throws Exception;
  }

  private static void expectVerifyError(String name, Thrower thrower)
      throws Exception {
    try {
      thrower.run();
    } catch (VerifyError expected) {
      return;
    }
    throw new RuntimeException("expected VerifyError: " + name);
  }

  private static void expectClassFormatError(String name, Thrower thrower)
      throws Exception {
    try {
      thrower.run();
    } catch (ClassFormatError expected) {
      return;
    }
    throw new RuntimeException("expected ClassFormatError: " + name);
  }

  private static void expectUnsupportedClassVersionError(String name,
                                                          Thrower thrower)
      throws Exception {
    try {
      thrower.run();
    } catch (UnsupportedClassVersionError expected) {
      return;
    }
    throw new RuntimeException("expected UnsupportedClassVersionError: " + name);
  }

  private static Class define(String name, byte[] bytes) {
    return SystemClassSpace.getClass(defineVM(name, bytes));
  }

  private static VMClass defineVM(String name, byte[] bytes) {
    return Classes.defineVMClass(
        SystemClassSpace.appClassSpace(), bytes, 0, bytes.length);
  }

  private static byte[] returnVoidCode() throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    Stream.write2(out, 0); // max stack
    Stream.write2(out, 0); // max locals
    Stream.write4(out, 1); // code length
    Stream.write1(out, Assembler.return_);
    Stream.write2(out, 0); // exception handler table length
    Stream.write2(out, 0); // attribute count
    return out.toByteArray();
  }

  private static int addMethodHandle(List<PoolEntry> pool,
                                     final int kind,
                                     final int referenceIndex) {
    return ConstantPool.add(pool, new PoolEntry() {
      public void writeTo(OutputStream out) throws IOException {
        Stream.write1(out, constantMethodHandle());
        Stream.write1(out, kind);
        Stream.write2(out, referenceIndex + 1);
      }
    });
  }

  private static int addMethodType(List<PoolEntry> pool, String spec) {
    final int descriptorIndex = ConstantPool.addUtf8(pool, spec);
    return ConstantPool.add(pool, new PoolEntry() {
      public void writeTo(OutputStream out) throws IOException {
        Stream.write1(out, constantMethodType());
        Stream.write2(out, descriptorIndex + 1);
      }
    });
  }

  private static int addInvokeDynamic(List<PoolEntry> pool,
                                      final int bootstrapIndex,
                                      final int nameAndTypeIndex) {
    return ConstantPool.add(pool, new PoolEntry() {
      public void writeTo(OutputStream out) throws IOException {
        Stream.write1(out, constantInvokeDynamic());
        Stream.write2(out, bootstrapIndex);
        Stream.write2(out, nameAndTypeIndex + 1);
      }
    });
  }

  private static byte[] makeClass(String name,
                                  List<PoolEntry> pool,
                                  FieldData[] fields,
                                  MethodData[] methods)
      throws IOException {
    return makeClassWithFlags(name,
                              Assembler.ACC_PUBLIC,
                              pool,
                              fields,
                              methods);
  }

  private static byte[] makeClassWithFlags(String name,
                                           int flags,
                                           List<PoolEntry> pool,
                                           FieldData[] fields,
                                           MethodData[] methods)
      throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    int className = ConstantPool.addClass(pool, name);
    int superName = ConstantPool.addClass(pool, "java/lang/Object");
    int codeName = ConstantPool.addUtf8(pool, "Code");

    Stream.write4(out, 0xCAFEBABE);
    Stream.write2(out, 0); // minor version
    Stream.write2(out, 50); // major version
    Stream.write2(out, pool.size() + 1);
    for (PoolEntry e : pool) {
      e.writeTo(out);
    }
    Stream.write2(out, flags);
    Stream.write2(out, className + 1);
    Stream.write2(out, superName + 1);
    Stream.write2(out, 0); // interfaces
    Stream.write2(out, fields.length);
    for (FieldData f : fields) {
      Stream.write2(out, f.flags);
      Stream.write2(out, f.nameIndex + 1);
      Stream.write2(out, f.specIndex + 1);
      Stream.write2(out, 0); // attributes
    }
    Stream.write2(out, methods.length);
    for (MethodData m : methods) {
      Stream.write2(out, m.flags);
      Stream.write2(out, m.nameIndex + 1);
      Stream.write2(out, m.specIndex + 1);
      Stream.write2(out, 1); // attributes
      Stream.write2(out, codeName + 1);
      Stream.write4(out, m.code.length);
      out.write(m.code);
    }
    Stream.write2(out, 0); // class attributes
    return out.toByteArray();
  }

  private static byte[] makeClassWithVersion(int minorVersion,
                                              int majorVersion)
      throws IOException {
    List<PoolEntry> pool = new ArrayList<PoolEntry>();
    int className = ConstantPool.addClass(pool, "VerifierProfile$VersionTest");
    int superName = ConstantPool.addClass(pool, "java/lang/Object");

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    Stream.write4(out, 0xCAFEBABE);
    Stream.write2(out, minorVersion);
    Stream.write2(out, majorVersion);
    Stream.write2(out, pool.size() + 1);
    for (PoolEntry e : pool) {
      e.writeTo(out);
    }
    Stream.write2(out, Assembler.ACC_PUBLIC);
    Stream.write2(out, className + 1);
    Stream.write2(out, superName + 1);
    Stream.write2(out, 0); // interfaces
    Stream.write2(out, 0); // fields
    Stream.write2(out, 0); // methods
    Stream.write2(out, 0); // class attributes
    return out.toByteArray();
  }

  private static byte[] makeForbiddenInternalFieldDescriptor()
      throws IOException {
    List<PoolEntry> pool = new ArrayList<PoolEntry>();
    FieldData[] fields = new FieldData[] {
      new FieldData(Assembler.ACC_PUBLIC,
                    ConstantPool.addUtf8(pool, "traces"),
                    ConstantPool.addUtf8(pool, "Ljava/internal/Traces;"))
    };
    return makeClass("VerifierProfile$ForbiddenInternalFieldDescriptor",
                     pool,
                     fields,
                     new MethodData[0]);
  }

  private static byte[] makeStaticStringField() throws IOException {
    List<PoolEntry> pool = new ArrayList<PoolEntry>();
    FieldData[] fields = new FieldData[] {
      new FieldData(Assembler.ACC_PUBLIC | Assembler.ACC_STATIC,
                    ConstantPool.addUtf8(pool, "name"),
                    ConstantPool.addUtf8(pool, "Ljava/lang/String;"))
    };
    return makeClass("VerifierProfile$StaticStringField",
                     pool,
                     fields,
                     new MethodData[0]);
  }

  private static byte[] makeClassWithBootstrapMethods(String className,
                                                      List<PoolEntry> pool,
                                                      int[][] methods)
      throws IOException {
    int name = ConstantPool.addClass(pool, className);
    int superName = ConstantPool.addClass(pool, "java/lang/Object");
    int attributeName = ConstantPool.addUtf8(pool, "BootstrapMethods");

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    Stream.write4(out, 0xCAFEBABE);
    Stream.write2(out, 0); // minor version
    Stream.write2(out, 50); // major version
    Stream.write2(out, pool.size() + 1);
    for (PoolEntry e : pool) {
      e.writeTo(out);
    }
    Stream.write2(out, Assembler.ACC_PUBLIC);
    Stream.write2(out, name + 1);
    Stream.write2(out, superName + 1);
    Stream.write2(out, 0); // interfaces
    Stream.write2(out, 0); // fields
    Stream.write2(out, 0); // methods
    Stream.write2(out, 1); // class attributes
    Stream.write2(out, attributeName + 1);

    ByteArrayOutputStream body = new ByteArrayOutputStream();
    Stream.write2(body, methods.length);
    for (int i = 0; i < methods.length; ++i) {
      int[] method = methods[i];
      Stream.write2(body, method[0] + 1);
      Stream.write2(body, method.length - 1);
      for (int j = 1; j < method.length; ++j) {
        Stream.write2(body, method[j] + 1);
      }
    }
    byte[] data = body.toByteArray();
    Stream.write4(out, data.length);
    out.write(data);
    return out.toByteArray();
  }

  private static byte[] makeForbiddenClassReference(String owner)
      throws IOException {
    List<PoolEntry> pool = new ArrayList<PoolEntry>();
    ConstantPool.addMethodRef(pool,
                              owner,
                              "forbidden",
                              "()V");
    return makeClass("VerifierProfile$ForbiddenClassReference",
                     pool,
                     new FieldData[0],
                     new MethodData[0]);
  }

  private static byte[] makeEmptyClass(String name) throws IOException {
    return makeClass(name,
                     new ArrayList<PoolEntry>(),
                     new FieldData[0],
                     new MethodData[0]);
  }

  private static byte[] makeForbiddenClassMethodReference(String name,
                                                          String spec)
      throws IOException {
    List<PoolEntry> pool = new ArrayList<PoolEntry>();
    ConstantPool.addMethodRef(pool,
                              "java/lang/Class",
                              name,
                              spec);
    return makeClass("VerifierProfile$ForbiddenClassMethodReference",
                     pool,
                     new FieldData[0],
                     new MethodData[0]);
  }

  private static byte[] makeForbiddenFieldDescriptor() throws IOException {
    List<PoolEntry> pool = new ArrayList<PoolEntry>();
    FieldData[] fields = new FieldData[] {
      new FieldData(Assembler.ACC_PUBLIC,
                    ConstantPool.addUtf8(pool, "runtime"),
                    ConstantPool.addUtf8(pool, "Ljava/lang/Runtime;"))
    };
    return makeClass("VerifierProfile$ForbiddenFieldDescriptor",
                     pool,
                     fields,
                     new MethodData[0]);
  }

  private static byte[] makeForbiddenMethodDescriptor() throws IOException {
    List<PoolEntry> pool = new ArrayList<PoolEntry>();
    MethodData[] methods = new MethodData[] {
      new MethodData(Assembler.ACC_PUBLIC | Assembler.ACC_STATIC,
                     ConstantPool.addUtf8(pool, "call"),
                     ConstantPool.addUtf8(pool, "(Ljava/lang/Thread;)V"),
                     returnVoidCode())
    };
    return makeClass("VerifierProfile$ForbiddenMethodDescriptor",
                     pool,
                     new FieldData[0],
                     methods);
  }

  private static byte[] makeForbiddenClassAttribute(String attribute)
      throws IOException {
    List<PoolEntry> pool = new ArrayList<PoolEntry>();
    int name = ConstantPool.addClass(pool, "VerifierProfile$ForbiddenAttribute");
    int superName = ConstantPool.addClass(pool, "java/lang/Object");
    int attributeName = ConstantPool.addUtf8(pool, attribute);

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    Stream.write4(out, 0xCAFEBABE);
    Stream.write2(out, 0); // minor version
    Stream.write2(out, 50); // major version
    Stream.write2(out, pool.size() + 1);
    for (PoolEntry e : pool) {
      e.writeTo(out);
    }
    Stream.write2(out, Assembler.ACC_PUBLIC);
    Stream.write2(out, name + 1);
    Stream.write2(out, superName + 1);
    Stream.write2(out, 0); // interfaces
    Stream.write2(out, 0); // fields
    Stream.write2(out, 0); // methods
    Stream.write2(out, 1); // class attributes
    Stream.write2(out, attributeName + 1);
    Stream.write4(out, 0); // attribute length
    return out.toByteArray();
  }

  private static byte[] makeForbiddenBootstrapMethod() throws IOException {
    List<PoolEntry> pool = new ArrayList<PoolEntry>();
    int methodRef = ConstantPool.addMethodRef(pool,
                                             "java/lang/String",
                                             "valueOf",
                                             "(I)Ljava/lang/String;");
    int handle = addMethodHandle(pool, refInvokeStatic(), methodRef);
    return makeClassWithBootstrapMethods(
        "VerifierProfile$ForbiddenBootstrapMethod",
        pool,
        new int[][] { new int[] { handle } });
  }

  private static byte[] makeForbiddenMethodTypeConstant()
      throws IOException {
    List<PoolEntry> pool = new ArrayList<PoolEntry>();
    addMethodType(pool, "()V");
    return makeClass("VerifierProfile$ForbiddenMethodTypeConstant",
                     pool,
                     new FieldData[0],
                     new MethodData[0]);
  }

  private static byte[] makeMissingBootstrapMethodsAttribute()
      throws IOException {
    List<PoolEntry> pool = new ArrayList<PoolEntry>();
    int nameAndType = ConstantPool.addNameAndType(pool,
                                                  "make",
                                                  "()Ljava/lang/Object;");
    addInvokeDynamic(pool, 0, nameAndType);
    return makeClass("VerifierProfile$MissingBootstrapMethods",
                     pool,
                     new FieldData[0],
                     new MethodData[0]);
  }

  private static byte[] makeDuplicateMethods() throws IOException {
    List<PoolEntry> pool = new ArrayList<PoolEntry>();
    int name = ConstantPool.addUtf8(pool, "same");
    int spec = ConstantPool.addUtf8(pool, "()V");
    MethodData method = new MethodData(Assembler.ACC_PUBLIC
                                           | Assembler.ACC_STATIC,
                                       name,
                                       spec,
                                       returnVoidCode());
    return makeClass("VerifierProfile$DuplicateMethods",
                     pool,
                     new FieldData[0],
                     new MethodData[] { method, method });
  }

  private static byte[] makeSynchronizedMethod() throws IOException {
    return makeClassWithRawMethod("VerifierProfile$SynchronizedMethod",
                                  new ArrayList<PoolEntry>(),
                                  Assembler.ACC_PUBLIC | accSynchronized(),
                                  "locked",
                                  "()V",
                                  true);
  }

  private static byte[] makeNativeMethod() throws IOException {
    return makeClassWithRawMethod("VerifierProfile$NativeMethod",
                                  new ArrayList<PoolEntry>(),
                                  Assembler.ACC_PUBLIC | accNative(),
                                  "nativeMethod",
                                  "()V",
                                  false);
  }

  private static byte[] makeFinalizerMethod() throws IOException {
    return makeClassWithRawMethod("VerifierProfile$FinalizerMethod",
                                  new ArrayList<PoolEntry>(),
                                  accProtected(),
                                  "finalize",
                                  "()V",
                                  true);
  }

  private static byte[] makeEnumClass() throws IOException {
    return makeClassWithFlags("VerifierProfile$EnumClass",
                              Assembler.ACC_PUBLIC | accEnum(),
                              new ArrayList<PoolEntry>(),
                              new FieldData[0],
                              new MethodData[0]);
  }

  private static byte[] makeClassWithRawMethod(String className,
                                               List<PoolEntry> pool,
                                               int flags,
                                               String methodName,
                                               String methodSpec,
                                               boolean withCode)
      throws IOException {
    int name = ConstantPool.addClass(pool, className);
    int superName = ConstantPool.addClass(pool, "java/lang/Object");
    int methodNameIndex = ConstantPool.addUtf8(pool, methodName);
    int methodSpecIndex = ConstantPool.addUtf8(pool, methodSpec);
    int codeName = ConstantPool.addUtf8(pool, "Code");

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    Stream.write4(out, 0xCAFEBABE);
    Stream.write2(out, 0); // minor version
    Stream.write2(out, 50); // major version
    Stream.write2(out, pool.size() + 1);
    for (PoolEntry e : pool) {
      e.writeTo(out);
    }
    Stream.write2(out, Assembler.ACC_PUBLIC);
    Stream.write2(out, name + 1);
    Stream.write2(out, superName + 1);
    Stream.write2(out, 0); // interfaces
    Stream.write2(out, 0); // fields
    Stream.write2(out, 1); // methods
    Stream.write2(out, flags);
    Stream.write2(out, methodNameIndex + 1);
    Stream.write2(out, methodSpecIndex + 1);
    if (withCode) {
      byte[] code = returnVoidCode();
      Stream.write2(out, 1);
      Stream.write2(out, codeName + 1);
      Stream.write4(out, code.length);
      out.write(code);
    } else {
      Stream.write2(out, 0);
    }
    Stream.write2(out, 0); // class attributes
    return out.toByteArray();
  }

  private static byte[] makeInvalidClinitDescriptor() throws IOException {
    return makeClassWithRawMethod("VerifierProfile$InvalidClinitDescriptor",
                                  new ArrayList<PoolEntry>(),
                                  Assembler.ACC_STATIC,
                                  "<clinit>",
                                  "(I)V",
                                  true);
  }

  private static byte[] makeApplicationClinit() throws IOException {
    return makeClassWithRawMethod("VerifierProfile$ApplicationClinit",
                                  new ArrayList<PoolEntry>(),
                                  Assembler.ACC_STATIC,
                                  "<clinit>",
                                  "()V",
                                  true);
  }

  private static byte[] makeNonStaticClinit() throws IOException {
    return makeClassWithRawMethod("VerifierProfile$NonStaticClinit",
                                  new ArrayList<PoolEntry>(),
                                  Assembler.ACC_PUBLIC,
                                  "<clinit>",
                                  "()V",
                                  true);
  }

  private static byte[] makeNativeClinit() throws IOException {
    return makeClassWithRawMethod("VerifierProfile$NativeClinit",
                                  new ArrayList<PoolEntry>(),
                                  Assembler.ACC_STATIC | accNative(),
                                  "<clinit>",
                                  "()V",
                                  true);
  }

  private static byte[] makeSynchronizedClinit() throws IOException {
    return makeClassWithRawMethod("VerifierProfile$SynchronizedClinit",
                                  new ArrayList<PoolEntry>(),
                                  Assembler.ACC_STATIC | accSynchronized(),
                                  "<clinit>",
                                  "()V",
                                  true);
  }

  private static byte[] makeAbstractClinit() throws IOException {
    return makeClassWithRawMethod("VerifierProfile$AbstractClinit",
                                  new ArrayList<PoolEntry>(),
                                  Assembler.ACC_STATIC | accAbstract(),
                                  "<clinit>",
                                  "()V",
                                  true);
  }

  private static byte[] makeClinitWithoutCode() throws IOException {
    return makeClassWithRawMethod("VerifierProfile$ClinitWithoutCode",
                                  new ArrayList<PoolEntry>(),
                                  Assembler.ACC_STATIC,
                                  "<clinit>",
                                  "()V",
                                  false);
  }

  private static byte[] makeInvalidConstructorDescriptor() throws IOException {
    return makeClassWithRawMethod("VerifierProfile$InvalidConstructorDescriptor",
                                  new ArrayList<PoolEntry>(),
                                  Assembler.ACC_PUBLIC,
                                  "<init>",
                                  "()I",
                                  true);
  }

  private static byte[] makeStaticConstructor() throws IOException {
    return makeClassWithRawMethod("VerifierProfile$StaticConstructor",
                                  new ArrayList<PoolEntry>(),
                                  Assembler.ACC_STATIC,
                                  "<init>",
                                  "()V",
                                  true);
  }

  private static byte[] makeForbiddenReflectionReference() throws IOException {
    List<PoolEntry> pool = new ArrayList<PoolEntry>();
    FieldData[] fields = new FieldData[] {
      new FieldData(Assembler.ACC_PUBLIC,
                    ConstantPool.addUtf8(pool, "method"),
                    ConstantPool.addUtf8(pool, "Ljava/lang/reflect/Method;"))
    };
    return makeClass("VerifierProfile$ForbiddenReflectionReference",
                     pool,
                     fields,
                     new MethodData[0]);
  }

  private static byte[] makeStaticField() throws IOException {
    List<PoolEntry> pool = new ArrayList<PoolEntry>();
    FieldData[] fields = new FieldData[] {
      new FieldData(Assembler.ACC_PUBLIC | Assembler.ACC_STATIC,
                    ConstantPool.addUtf8(pool, "counter"),
                    ConstantPool.addUtf8(pool, "I"))
    };
    return makeClass("VerifierProfile$StaticField",
                     pool,
                     fields,
                     new MethodData[0]);
  }

  private static byte[] makeStaticFinalFieldWithoutConstantValue()
      throws IOException {
    List<PoolEntry> pool = new ArrayList<PoolEntry>();
    FieldData[] fields = new FieldData[] {
      new FieldData(Assembler.ACC_PUBLIC | Assembler.ACC_STATIC | accFinal(),
                    ConstantPool.addUtf8(pool, "counter"),
                    ConstantPool.addUtf8(pool, "I"))
    };
    return makeClass("VerifierProfile$StaticFinalWithoutConstantValue",
                     pool,
                     fields,
                     new MethodData[0]);
  }

  private static byte[] makeStaticFinalConstantField() throws IOException {
    String className = "VerifierProfile$StaticFinalConstant";
    List<PoolEntry> pool = new ArrayList<PoolEntry>();
    int fieldName = ConstantPool.addUtf8(pool, "answer");
    int fieldSpec = ConstantPool.addUtf8(pool, "I");
    int value = ConstantPool.addInteger(pool, 42);
    int constantValue = ConstantPool.addUtf8(pool, "ConstantValue");
    int methodName = ConstantPool.addUtf8(pool, "read");
    int methodSpec = ConstantPool.addUtf8(pool, "()I");
    int fieldRef = ConstantPool.addFieldRef(pool, className, "answer", "I");
    int codeName = ConstantPool.addUtf8(pool, "Code");
    int name = ConstantPool.addClass(pool, className);
    int superName = ConstantPool.addClass(pool, "java/lang/Object");

    ByteArrayOutputStream code = new ByteArrayOutputStream();
    Stream.write2(code, 1); // max stack
    Stream.write2(code, 0); // max locals
    Stream.write4(code, 4); // code length
    Stream.write1(code, opcodeGetstatic());
    Stream.write2(code, fieldRef + 1);
    Stream.write1(code, Assembler.ireturn);
    Stream.write2(code, 0); // exception handler table length
    Stream.write2(code, 0); // code attribute count
    byte[] codeBytes = code.toByteArray();

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    Stream.write4(out, 0xCAFEBABE);
    Stream.write2(out, 0); // minor version
    Stream.write2(out, 50); // major version
    Stream.write2(out, pool.size() + 1);
    for (PoolEntry e : pool) {
      e.writeTo(out);
    }
    Stream.write2(out, Assembler.ACC_PUBLIC);
    Stream.write2(out, name + 1);
    Stream.write2(out, superName + 1);
    Stream.write2(out, 0); // interfaces
    Stream.write2(out, 1); // fields
    Stream.write2(out, Assembler.ACC_PUBLIC | Assembler.ACC_STATIC | accFinal());
    Stream.write2(out, fieldName + 1);
    Stream.write2(out, fieldSpec + 1);
    Stream.write2(out, 1); // field attributes
    Stream.write2(out, constantValue + 1);
    Stream.write4(out, 2);
    Stream.write2(out, value + 1);
    Stream.write2(out, 1); // methods
    Stream.write2(out, Assembler.ACC_PUBLIC | Assembler.ACC_STATIC);
    Stream.write2(out, methodName + 1);
    Stream.write2(out, methodSpec + 1);
    Stream.write2(out, 1); // method attributes
    Stream.write2(out, codeName + 1);
    Stream.write4(out, codeBytes.length);
    out.write(codeBytes);
    Stream.write2(out, 0); // class attributes
    return out.toByteArray();
  }

  private static int invokeStaticInt(VMClass class_, String name, String spec) {
    VMMethod method = Classes.findMethod(class_, name, spec);
    if (method == null) {
      throw new RuntimeException("missing method: " + name + spec);
    }

    return ((Integer) Classes.invokeVMMethod(method, null, new Object[0]))
        .intValue();
  }

  public static void main(String[] args) throws Exception {
    expectVerifyError("forbidden class ref", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ForbiddenClassReference",
               makeForbiddenClassReference("java/lang/Runtime"));
      }
    });

    expectVerifyError("forbidden hash collection ref", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ForbiddenClassReference",
               makeForbiddenClassReference("java/util/HashMap"));
      }
    });

    expectVerifyError("forbidden file descriptor ref", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ForbiddenClassReference",
               makeForbiddenClassReference("java/io/FileDescriptor"));
      }
    });

    expectVerifyError("forbidden file exception ref", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ForbiddenClassReference",
               makeForbiddenClassReference("java/io/FileNotFoundException"));
      }
    });

    final String[] forbiddenStreamDecorators = new String[] {
      "java/io/FilterInputStream",
      "java/io/FilterOutputStream",
      "java/io/FilterReader",
      "java/io/LineNumberReader",
      "java/io/PushbackReader",
    };
    for (int i = 0; i < forbiddenStreamDecorators.length; ++i) {
      final String owner = forbiddenStreamDecorators[i];
      expectVerifyError("forbidden stream decorator ref", new Thrower() {
        public void run() throws Exception {
          define("VerifierProfile$ForbiddenClassReference",
                 makeForbiddenClassReference(owner));
        }
      });
    }

    expectVerifyError("forbidden weak reference ref", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ForbiddenClassReference",
               makeForbiddenClassReference("java/lang/ref/WeakReference"));
      }
    });

    expectVerifyError("forbidden legacy collection ref", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ForbiddenClassReference",
               makeForbiddenClassReference("java/util/Vector"));
      }
    });

    expectVerifyError("forbidden enum collection ref", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ForbiddenClassReference",
               makeForbiddenClassReference("java/util/EnumSet"));
      }
    });

    expectVerifyError("forbidden abstract map shell ref", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ForbiddenClassReference",
               makeForbiddenClassReference("java/util/AbstractMap"));
      }
    });

    expectVerifyError("forbidden partial navigable map ref", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ForbiddenClassReference",
               makeForbiddenClassReference("java/util/NavigableMap"));
      }
    });

    expectVerifyError("forbidden sequential-list shell ref", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ForbiddenClassReference",
               makeForbiddenClassReference("java/util/AbstractSequentialList"));
      }
    });

    expectVerifyError("forbidden string buffer ref", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ForbiddenClassReference",
               makeForbiddenClassReference("java/lang/StringBuffer"));
      }
    });

    expectVerifyError("forbidden class classification helper ref",
        new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ForbiddenClassReference",
               makeForbiddenClassReference("java/lang/Class$ClassType"));
      }
    });

    expectVerifyError("forbidden package metadata ref", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ForbiddenClassReference",
               makeForbiddenClassReference("java/lang/Package"));
      }
    });

    final String[] forbiddenBootOnlySymbols = new String[] {
      "java/io/Serializable",
      "java/lang/Cloneable",
      "java/lang/CloneNotSupportedException",
      "java/lang/ClassNotFoundException",
    };
    for (int i = 0; i < forbiddenBootOnlySymbols.length; ++i) {
      final String owner = forbiddenBootOnlySymbols[i];
      expectVerifyError("forbidden boot-only symbol ref", new Thrower() {
        public void run() throws Exception {
          define("VerifierProfile$ForbiddenClassReference",
                 makeForbiddenClassReference(owner));
        }
      });
    }

    final String[] forbiddenInternalClasses = new String[] {
      "java/internal/Classes",
      "java/internal/SystemClassSpace",
      "java/internal/VMClass",
      "java/internal/Memory",
    };
    for (int i = 0; i < forbiddenInternalClasses.length; ++i) {
      final String owner = forbiddenInternalClasses[i];
      expectVerifyError("forbidden java.internal internal ref", new Thrower() {
        public void run() throws Exception {
          define("VerifierProfile$ForbiddenClassReference",
                 makeForbiddenClassReference(owner));
        }
      });
    }

    expectVerifyError("forbidden java.internal package class", new Thrower() {
      public void run() throws Exception {
        define("java/internal/ForbiddenContractClass",
               makeEmptyClass("java/internal/ForbiddenContractClass"));
      }
    });

    final String[][] forbiddenClassMethods = new String[][] {
      new String[] { "forName", "(Ljava/lang/String;)Ljava/lang/Class;" },
      new String[] { "getPackage", "()Ljava/lang/Package;" },
      new String[] { "getDeclaredClasses", "()[Ljava/lang/Class;" },
      new String[] { "getDeclaringClass", "()Ljava/lang/Class;" },
      new String[] { "getEnclosingClass", "()Ljava/lang/Class;" },
      new String[] { "desiredAssertionStatus", "()Z" },
      new String[] { "asSubclass", "(Ljava/lang/Class;)Ljava/lang/Class;" },
      new String[] { "cast", "(Ljava/lang/Object;)Ljava/lang/Object;" },
    };
    for (int i = 0; i < forbiddenClassMethods.length; ++i) {
      final String methodName = forbiddenClassMethods[i][0];
      final String methodSpec = forbiddenClassMethods[i][1];
      expectVerifyError("forbidden Class." + methodName + " ref",
          new Thrower() {
        public void run() throws Exception {
          define("VerifierProfile$ForbiddenClassMethodReference",
                 makeForbiddenClassMethodReference(methodName, methodSpec));
        }
      });
    }

    expectVerifyError("forbidden security exception ref", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ForbiddenClassReference",
               makeForbiddenClassReference("java/lang/SecurityException"));
      }
    });

    expectVerifyError("forbidden illegal-access exception ref", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ForbiddenClassReference",
               makeForbiddenClassReference("java/lang/IllegalAccessException"));
      }
    });

    expectVerifyError("forbidden no-such-field exception ref", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ForbiddenClassReference",
               makeForbiddenClassReference("java/lang/NoSuchFieldException"));
      }
    });

    expectVerifyError("forbidden no-such-method exception ref", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ForbiddenClassReference",
               makeForbiddenClassReference("java/lang/NoSuchMethodException"));
      }
    });

    expectVerifyError("forbidden interrupted exception ref", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ForbiddenClassReference",
               makeForbiddenClassReference("java/lang/InterruptedException"));
      }
    });

    expectVerifyError("forbidden thread death ref", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ForbiddenClassReference",
               makeForbiddenClassReference("java/lang/ThreadDeath"));
      }
    });

    expectVerifyError("forbidden thread state exception ref", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ForbiddenClassReference",
               makeForbiddenClassReference(
                   "java/lang/IllegalThreadStateException"));
      }
    });

    expectVerifyError("forbidden type-not-present exception ref", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ForbiddenClassReference",
               makeForbiddenClassReference(
                   "java/lang/TypeNotPresentException"));
      }
    });

    expectVerifyError("forbidden field descriptor", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ForbiddenFieldDescriptor",
               makeForbiddenFieldDescriptor());
      }
    });

    expectVerifyError("forbidden method descriptor", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ForbiddenMethodDescriptor",
               makeForbiddenMethodDescriptor());
      }
    });

    expectVerifyError("forbidden attribute", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ForbiddenAttribute",
               makeForbiddenClassAttribute("NestMembers"));
      }
    });

    expectVerifyError("forbidden bootstrap method", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ForbiddenBootstrapMethod",
               makeForbiddenBootstrapMethod());
      }
    });

    expectVerifyError("forbidden method type constant", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ForbiddenMethodTypeConstant",
               makeForbiddenMethodTypeConstant());
      }
    });

    expectVerifyError("missing BootstrapMethods", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$MissingBootstrapMethods",
               makeMissingBootstrapMethodsAttribute());
      }
    });

    expectClassFormatError("duplicate methods", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$DuplicateMethods", makeDuplicateMethods());
      }
    });

    expectVerifyError("synchronized method", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$SynchronizedMethod",
               makeSynchronizedMethod());
      }
    });

    expectVerifyError("native method", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$NativeMethod", makeNativeMethod());
      }
    });

    expectVerifyError("finalizer method", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$FinalizerMethod", makeFinalizerMethod());
      }
    });

    expectVerifyError("enum class", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$EnumClass", makeEnumClass());
      }
    });

    expectVerifyError("application clinit", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ApplicationClinit", makeApplicationClinit());
      }
    });

    expectVerifyError("invalid clinit descriptor", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$InvalidClinitDescriptor",
               makeInvalidClinitDescriptor());
      }
    });

    expectVerifyError("non-static clinit", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$NonStaticClinit", makeNonStaticClinit());
      }
    });

    expectVerifyError("native clinit", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$NativeClinit", makeNativeClinit());
      }
    });

    expectVerifyError("synchronized clinit", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$SynchronizedClinit",
               makeSynchronizedClinit());
      }
    });

    expectVerifyError("abstract clinit", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$AbstractClinit", makeAbstractClinit());
      }
    });

    expectVerifyError("clinit without code", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ClinitWithoutCode", makeClinitWithoutCode());
      }
    });

    expectClassFormatError("invalid constructor descriptor", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$InvalidConstructorDescriptor",
               makeInvalidConstructorDescriptor());
      }
    });

    expectClassFormatError("static constructor", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$StaticConstructor", makeStaticConstructor());
      }
    });

    expectVerifyError("forbidden reflection descriptor", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ForbiddenReflectionReference",
               makeForbiddenReflectionReference());
      }
    });

    expectVerifyError("static field", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$StaticField", makeStaticField());
      }
    });

    expectVerifyError("static final without ConstantValue", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$StaticFinalWithoutConstantValue",
               makeStaticFinalFieldWithoutConstantValue());
      }
    });

    VMClass constants = defineVM("VerifierProfile$StaticFinalConstant",
                                 makeStaticFinalConstantField());
    if (invokeStaticInt(constants, "read", "()I") != 42) {
      throw new RuntimeException("static final constant read failed");
    }

    // Class-file version tests.
    // Java 8 (major=52, minor=0) must be accepted.
    define("VerifierProfile$VersionTest", makeClassWithVersion(0, 52));

    // Java 1.1 (major=45, minor=3) must be accepted — earliest admitted.
    define("VerifierProfile$VersionTest", makeClassWithVersion(3, 45));

    // Java 9+ (major=53) must be rejected with UnsupportedClassVersionError.
    expectUnsupportedClassVersionError("java 9+ class file major", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$VersionTest", makeClassWithVersion(0, 53));
      }
    });

    // Pre-Java-1.1 (major=44) must be rejected with UnsupportedClassVersionError.
    expectUnsupportedClassVersionError("pre-java-1.1 class file major",
        new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$VersionTest", makeClassWithVersion(0, 44));
      }
    });

    // Java preview minor (0xFFFF) must be rejected with UnsupportedClassVersionError.
    expectUnsupportedClassVersionError("java preview minor version", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$VersionTest", makeClassWithVersion(0xFFFF, 52));
      }
    });

    // Additional forbidden class ref tests for completeness.
    expectVerifyError("forbidden Thread class ref", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ForbiddenClassReference",
               makeForbiddenClassReference("java/lang/Thread"));
      }
    });

    expectVerifyError("forbidden ClassLoader class ref", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ForbiddenClassReference",
               makeForbiddenClassReference("java/lang/ClassLoader"));
      }
    });

    expectVerifyError("forbidden invoke/MethodHandle class ref", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ForbiddenClassReference",
               makeForbiddenClassReference("java/lang/invoke/MethodHandle"));
      }
    });

    expectVerifyError("forbidden reflect/Field class ref", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ForbiddenClassReference",
               makeForbiddenClassReference("java/lang/reflect/Field"));
      }
    });

    // Stale avata/* namespace must be rejected in constant-pool class refs.
    expectVerifyError("stale avata/* class ref", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ForbiddenClassReference",
               makeForbiddenClassReference("avata/SomeClass"));
      }
    });

    // Stale avata/* namespace must be rejected as a declared class name.
    expectVerifyError("stale avata/* declared class name", new Thrower() {
      public void run() throws Exception {
        define("avata/ForbiddenContractClass",
               makeEmptyClass("avata/ForbiddenContractClass"));
      }
    });

    // java/internal/* in field descriptor must be rejected.
    expectVerifyError("forbidden java.internal field descriptor", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ForbiddenInternalFieldDescriptor",
               makeForbiddenInternalFieldDescriptor());
      }
    });

    // Static mutable String field must be rejected.
    expectVerifyError("static String field", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$StaticStringField", makeStaticStringField());
      }
    });

    // Additional forbidden class-file attribute tests.
    final String[] forbiddenAttributes = new String[] {
      "Module",
      "ModulePackages",
      "ModuleMainClass",
      "NestHost",
      "Record",
      "PermittedSubclasses",
    };
    for (int i = 0; i < forbiddenAttributes.length; ++i) {
      final String attr = forbiddenAttributes[i];
      expectVerifyError("forbidden attribute " + attr, new Thrower() {
        public void run() throws Exception {
          define("VerifierProfile$ForbiddenAttribute",
                 makeForbiddenClassAttribute(attr));
        }
      });
    }
  }
}
