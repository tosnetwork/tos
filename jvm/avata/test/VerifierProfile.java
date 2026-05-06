import avata.Assembler;
import avata.Assembler.FieldData;
import avata.Assembler.MethodData;
import avata.ConstantPool;
import avata.ConstantPool.PoolEntry;
import avata.Stream;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

public class VerifierProfile {
  private static final int CONSTANT_METHOD_HANDLE = 15;
  private static final int CONSTANT_METHOD_TYPE = 16;
  private static final int CONSTANT_INVOKE_DYNAMIC = 18;
  private static final int REF_INVOKE_STATIC = 6;
  private static final int ACC_SYNCHRONIZED = 0x0020;
  private static final int ACC_NATIVE = 0x0100;
  private static final int ACC_ABSTRACT = 0x0400;

  private static final String ALT_METAFACTORY_SPEC =
      "(Ljava/lang/invoke/MethodHandles$Lookup;"
      + "Ljava/lang/String;"
      + "Ljava/lang/invoke/MethodType;"
      + "[Ljava/lang/Object;)"
      + "Ljava/lang/invoke/CallSite;";

  private interface Thrower {
    void run() throws Exception;
  }

  private static class MyClassLoader extends ClassLoader {
    MyClassLoader(ClassLoader parent) {
      super(parent);
    }

    Class define(String name, byte[] bytes) {
      return super.defineClass(name, bytes, 0, bytes.length);
    }
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

  private static Class define(String name, byte[] bytes) {
    return new MyClassLoader(VerifierProfile.class.getClassLoader())
        .define(name, bytes);
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
        Stream.write1(out, CONSTANT_METHOD_HANDLE);
        Stream.write1(out, kind);
        Stream.write2(out, referenceIndex + 1);
      }
    });
  }

  private static int addMethodType(List<PoolEntry> pool, String spec) {
    final int descriptorIndex = ConstantPool.addUtf8(pool, spec);
    return ConstantPool.add(pool, new PoolEntry() {
      public void writeTo(OutputStream out) throws IOException {
        Stream.write1(out, CONSTANT_METHOD_TYPE);
        Stream.write2(out, descriptorIndex + 1);
      }
    });
  }

  private static int addInvokeDynamic(List<PoolEntry> pool,
                                      final int bootstrapIndex,
                                      final int nameAndTypeIndex) {
    return ConstantPool.add(pool, new PoolEntry() {
      public void writeTo(OutputStream out) throws IOException {
        Stream.write1(out, CONSTANT_INVOKE_DYNAMIC);
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
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    Assembler.writeClass(out,
                         pool,
                         ConstantPool.addClass(pool, name),
                         ConstantPool.addClass(pool, "java/lang/Object"),
                         new int[0],
                         fields,
                         methods);
    return out.toByteArray();
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

  private static byte[] makeForbiddenClassReference() throws IOException {
    List<PoolEntry> pool = new ArrayList<PoolEntry>();
    ConstantPool.addMethodRef(pool,
                              "java/lang/Runtime",
                              "getRuntime",
                              "()Ljava/lang/Runtime;");
    return makeClass("VerifierProfile$ForbiddenClassReference",
                     pool,
                     new FieldData[0],
                     new MethodData[0]);
  }

  private static byte[] makeForbiddenFieldDescriptor() throws IOException {
    List<PoolEntry> pool = new ArrayList<PoolEntry>();
    FieldData[] fields = new FieldData[] {
      new FieldData(Assembler.ACC_PUBLIC,
                    ConstantPool.addUtf8(pool, "socket"),
                    ConstantPool.addUtf8(pool, "Ljava/net/Socket;"))
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
    int handle = addMethodHandle(pool, REF_INVOKE_STATIC, methodRef);
    return makeClassWithBootstrapMethods(
        "VerifierProfile$ForbiddenBootstrapMethod",
        pool,
        new int[][] { new int[] { handle } });
  }

  private static byte[] makeForbiddenSerializableBootstrap()
      throws IOException {
    List<PoolEntry> pool = new ArrayList<PoolEntry>();
    int bootstrapRef = ConstantPool.addMethodRef(pool,
                                                "java/lang/invoke/"
                                                    + "LambdaMetafactory",
                                                "altMetafactory",
                                                ALT_METAFACTORY_SPEC);
    int bootstrap = addMethodHandle(pool, REF_INVOKE_STATIC, bootstrapRef);
    int methodType = addMethodType(pool, "()V");
    int implementationRef = ConstantPool.addMethodRef(
        pool, "VerifierProfile$ForbiddenSerializableBootstrap", "target", "()V");
    int implementation
        = addMethodHandle(pool, REF_INVOKE_STATIC, implementationRef);
    int serializableFlag = ConstantPool.addInteger(pool, 1);
    return makeClassWithBootstrapMethods(
        "VerifierProfile$ForbiddenSerializableBootstrap",
        pool,
        new int[][] {
          new int[] {
            bootstrap,
            methodType,
            implementation,
            methodType,
            serializableFlag
          }
        });
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
                                  Assembler.ACC_STATIC | ACC_NATIVE,
                                  "<clinit>",
                                  "()V",
                                  true);
  }

  private static byte[] makeSynchronizedClinit() throws IOException {
    return makeClassWithRawMethod("VerifierProfile$SynchronizedClinit",
                                  new ArrayList<PoolEntry>(),
                                  Assembler.ACC_STATIC | ACC_SYNCHRONIZED,
                                  "<clinit>",
                                  "()V",
                                  true);
  }

  private static byte[] makeAbstractClinit() throws IOException {
    return makeClassWithRawMethod("VerifierProfile$AbstractClinit",
                                  new ArrayList<PoolEntry>(),
                                  Assembler.ACC_STATIC | ACC_ABSTRACT,
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

  private static void validAllowedReflectionReference() throws Exception {
    List<PoolEntry> pool = new ArrayList<PoolEntry>();
    FieldData[] fields = new FieldData[] {
      new FieldData(Assembler.ACC_PUBLIC,
                    ConstantPool.addUtf8(pool, "method"),
                    ConstantPool.addUtf8(pool, "Ljava/lang/reflect/Method;"))
    };
    Class c = define("VerifierProfile$AllowedReflectionReference",
                     makeClass("VerifierProfile$AllowedReflectionReference",
                               pool,
                               fields,
                               new MethodData[0]));
    if (!"VerifierProfile$AllowedReflectionReference".equals(c.getName())) {
      throw new RuntimeException("wrong defined class name");
    }
  }

  public static void main(String[] args) throws Exception {
    expectVerifyError("forbidden class ref", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ForbiddenClassReference",
               makeForbiddenClassReference());
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

    expectVerifyError("forbidden serializable bootstrap", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$ForbiddenSerializableBootstrap",
               makeForbiddenSerializableBootstrap());
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

    expectClassFormatError("invalid clinit descriptor", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$InvalidClinitDescriptor",
               makeInvalidClinitDescriptor());
      }
    });

    expectClassFormatError("non-static clinit", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$NonStaticClinit", makeNonStaticClinit());
      }
    });

    expectClassFormatError("native clinit", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$NativeClinit", makeNativeClinit());
      }
    });

    expectClassFormatError("synchronized clinit", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$SynchronizedClinit",
               makeSynchronizedClinit());
      }
    });

    expectClassFormatError("abstract clinit", new Thrower() {
      public void run() throws Exception {
        define("VerifierProfile$AbstractClinit", makeAbstractClinit());
      }
    });

    expectClassFormatError("clinit without code", new Thrower() {
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

    validAllowedReflectionReference();
  }
}
