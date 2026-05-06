/* Copyright (c) 2008-2016, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.lang.invoke;

import static avata.Stream.write1;
import static avata.Stream.write2;
import static avata.Stream.write4;
import static avata.Stream.set4;
import static avata.Assembler.*;

import java.lang.reflect.Proxy;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.List;
import java.util.ArrayList;
import java.util.Iterator;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.IOException;

import avata.Classes;
import avata.ConstantPool;
import avata.Assembler;
import avata.ConstantPool.PoolEntry;
import avata.SystemClassLoader;

// Implements the Java 8 lambda translation strategy used by javac.

public class LambdaMetafactory {
  private static int nextNumber = 0;

  public static final int FLAG_SERIALIZABLE = 1;
  public static final int FLAG_MARKERS = 2;
  public static final int FLAG_BRIDGES = 4;

  private static Class resolveReturnInterface(MethodType type) {
    int index = 1;
    byte[] s = type.spec;

    while (s[index] != ')') ++ index;

    if (s[++ index] != 'L') throw new AssertionError();

    ++ index;

    int end = index + 1;
    while (s[end] != ';') ++ end;

    Class c = SystemClassLoader.getClass
      (Classes.loadVMClass(type.loader, s, index, end - index));

    if (! c.isInterface()) throw new AssertionError();

    return c;
  }

  private static int indexOf(int c, byte[] array) {
    int i = 0;
    while (array[i] != c) ++i;
    return i;
  }

  private static String constructorSpec(MethodType type) {
    return Classes.makeString(type.spec, 0, indexOf(')', type.spec) + 1) + "V";
  }

  private static byte[] makeFactoryCode(List<PoolEntry> pool,
                                        String className,
                                        String constructorSpec,
                                        MethodType type)
    throws IOException
  {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    write2(out, type.footprint() + 2); // max stack
    write2(out, type.footprint()); // max locals
    write4(out, 0); // length (we'll set the real value later)

    write1(out, new_);
    write2(out, ConstantPool.addClass(pool, className) + 1);
    write1(out, dup);

    for (MethodType.Parameter p: type.parameters()) {
      write1(out, p.load());
      write1(out, p.position());
    }

    write1(out, invokespecial);
    write2(out, ConstantPool.addMethodRef
           (pool, className, "<init>", constructorSpec) + 1);

    write1(out, areturn);

    write2(out, 0); // exception handler table length
    write2(out, 0); // attribute count

    byte[] result = out.toByteArray();
    set4(result, 4, result.length - 12);

    return result;
  }

  private static byte[] makeConstructorCode(List<PoolEntry> pool,
                                            String className,
                                            MethodType type)
    throws IOException
  {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    write2(out, 3); // max stack
    write2(out, type.footprint() + 1); // max locals
    write4(out, 0); // length (we'll set the real value later)

    write1(out, aload_0);
    write1(out, invokespecial);
    write2(out, ConstantPool.addMethodRef
           (pool, "java/lang/Object", "<init>", "()V") + 1);

    for (MethodType.Parameter p: type.parameters()) {
      write1(out, aload_0);
      write1(out, p.load());
      write1(out, p.position() + 1);
      write1(out, putfield);
      write2(out, ConstantPool.addFieldRef
             (pool, className, "field" + p.index(), p.spec()) + 1);
    }

    write1(out, return_);

    write2(out, 0); // exception handler table length
    write2(out, 0); // attribute count

    byte[] result = out.toByteArray();
    set4(result, 4, result.length - 12);

    return result;
  }

  private static void maybeBoxOrUnbox(ByteArrayOutputStream out,
                                      List<PoolEntry> pool,
                                      MethodType.TypeSpec from,
                                      MethodType.TypeSpec to)
    throws IOException
  {
    if (to.type().isPrimitive()) {
      if (! (from.type().isPrimitive() || "V".equals(to.spec()))) {
        write1(out, invokevirtual);

        try {
          switch (to.spec()) {
          case "Z":
            writeMethodReference(out, pool, Classes.toVMMethod
                                 (Boolean.class.getMethod("booleanValue")));
            break;

          case "B":
            writeMethodReference(out, pool, Classes.toVMMethod
                                 (Byte.class.getMethod("byteValue")));
            break;

          case "S":
            writeMethodReference(out, pool, Classes.toVMMethod
                                 (Short.class.getMethod("shortValue")));
            break;

          case "C":
            writeMethodReference(out, pool, Classes.toVMMethod
                                 (Character.class.getMethod("charValue")));
            break;

          case "I":
            writeMethodReference(out, pool, Classes.toVMMethod
                                 (Integer.class.getMethod("intValue")));
            break;

          case "F":
            writeMethodReference(out, pool, Classes.toVMMethod
                                 (Float.class.getMethod("floatValue")));
            break;

          case "J":
            writeMethodReference(out, pool, Classes.toVMMethod
                                 (Long.class.getMethod("longValue")));
            break;

          case "D":
            writeMethodReference(out, pool, Classes.toVMMethod
                                 (Double.class.getMethod("doubleValue")));
            break;

          default:
            throw new AssertionError("don't know how to auto-unbox to " + to.spec());
          }
        } catch (NoSuchMethodException e) {
          throw new Error(e);
        }
      }
    } else if (from.type().isPrimitive()) {
      write1(out, invokestatic);

      try {
        switch (from.spec()) {
        case "Z":
          writeMethodReference(out, pool, Classes.toVMMethod
                               (Boolean.class.getMethod
                                ("valueOf", Boolean.TYPE)));
          break;

        case "B":
          writeMethodReference(out, pool, Classes.toVMMethod
                               (Byte.class.getMethod
                                ("valueOf", Byte.TYPE)));
          break;

        case "S":
          writeMethodReference(out, pool, Classes.toVMMethod
                               (Short.class.getMethod
                                ("valueOf", Short.TYPE)));
          break;

        case "C":
          writeMethodReference(out, pool, Classes.toVMMethod
                               (Character.class.getMethod
                                ("valueOf", Character.TYPE)));
          break;

        case "I":
          writeMethodReference(out, pool, Classes.toVMMethod
                               (Integer.class.getMethod
                                ("valueOf", Integer.TYPE)));
          break;

        case "F":
          writeMethodReference(out, pool, Classes.toVMMethod
                               (Float.class.getMethod
                                ("valueOf", Float.TYPE)));
          break;

        case "J":
          writeMethodReference(out, pool, Classes.toVMMethod
                               (Long.class.getMethod
                                ("valueOf", Long.TYPE)));
          break;

        case "D":
          writeMethodReference(out, pool, Classes.toVMMethod
                               (Double.class.getMethod
                                ("valueOf", Double.TYPE)));
          break;

        default:
          throw new AssertionError("don't know how to autobox from " + from.spec());
        }
      } catch (NoSuchMethodException e) {
        throw new Error(e);
      }
    }
  }

  private static byte[] makeInvocationCode(List<PoolEntry> pool,
                                           String className,
                                           String constructorSpec,
                                           MethodType fieldType,
                                           MethodType localType,
                                           MethodHandle implementation)
    throws IOException
  {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    write2(out, fieldType.footprint()
           + localType.footprint() + 4); // max stack
    write2(out, localType.footprint() + 1); // max locals
    write4(out, 0); // length (we'll set the real value later)

    write1(out, aload_0);

    Iterator<MethodType.Parameter> dst = implementation.type().parameters().iterator();

    boolean skip = implementation.kind != MethodHandle.REF_invokeStatic;

    for (MethodType.Parameter p: fieldType.parameters()) {
      write1(out, aload_0);
      write1(out, getfield);
      write2(out, ConstantPool.addFieldRef
             (pool, className, "field" + p.index(), p.spec()) + 1);
      if (skip) {
        skip = false;
      } else {
        maybeBoxOrUnbox(out, pool, p, dst.next());
      }
    }

    for (MethodType.Parameter p: localType.parameters()) {
      write1(out, p.load());
      write1(out, p.position() + 1);
      if (skip) {
        skip = false;
      } else {
        maybeBoxOrUnbox(out, pool, p, dst.next());
      }
    }

    switch (implementation.kind) {
    case MethodHandle.REF_invokeVirtual:
      write1(out, invokevirtual);
      writeMethodReference(out, pool, implementation.method);
      break;

    case MethodHandle.REF_invokeStatic:
      write1(out, invokestatic);
      writeMethodReference(out, pool, implementation.method);
      break;

    case MethodHandle.REF_invokeSpecial:
      write1(out, invokespecial);
      writeMethodReference(out, pool, implementation.method);
      break;

    case MethodHandle.REF_newInvokeSpecial:
      write1(out, new_);
      write2(out, ConstantPool.addClass
             (pool,
              Classes.makeString
              (implementation.method.class_.name, 0,
               implementation.method.class_.name.length - 1)) + 1);
      write1(out, dup);
      write1(out, invokespecial);
      writeMethodReference(out, pool, implementation.method);
      break;

    case MethodHandle.REF_invokeInterface:
      write1(out, invokeinterface);
      writeInterfaceMethodReference(out, pool, implementation.method);
      write1(out, implementation.method.parameterFootprint);
      write1(out, 0);
      break;

    default: throw new AssertionError
        ("todo: implement '" + implementation.kind + "' per http://docs.oracle.com/javase/specs/jvms/se8/html/jvms-5.html#jvms-5.4.3.5");
    }

    if (implementation.kind != MethodHandle.REF_newInvokeSpecial) {
      maybeBoxOrUnbox(out, pool, implementation.type().result(), localType.result());
    }
    write1(out, localType.result().return_());

    write2(out, 0); // exception handler table length
    write2(out, 0); // attribute count

    byte[] result = out.toByteArray();
    set4(result, 4, result.length - 12);

    return result;
  }

  private static void writeMethodReference(OutputStream out,
                                           List<PoolEntry> pool,
                                           avata.VMMethod method)
    throws IOException
  {
    write2(out, ConstantPool.addMethodRef
           (pool,
            Classes.makeString(method.class_.name, 0,
                               method.class_.name.length - 1),
            Classes.makeString(method.name, 0,
                               method.name.length - 1),
            Classes.makeString(method.spec, 0,
                               method.spec.length - 1)) + 1);
  }

  private static void writeInterfaceMethodReference(OutputStream out,
                                                    List<PoolEntry> pool,
                                                    avata.VMMethod method)
    throws IOException
  {
    write2(out, ConstantPool.addInterfaceMethodRef
           (pool,
            Classes.makeString(method.class_.name, 0,
                               method.class_.name.length - 1),
            Classes.makeString(method.name, 0,
                               method.name.length - 1),
            Classes.makeString(method.spec, 0,
                               method.spec.length - 1)) + 1);
  }

  public static byte[] makeLambda(String invokedName,
                                  String invokedType,
                                  String methodType,
                                  String implementationClass,
                                  String implementationName,
                                  String implementationSpec,
                                  int implementationKind)
  {
    return makeLambda(invokedName,
                      new MethodType(invokedType),
                      new MethodType(methodType),
                      new MethodHandle(implementationClass,
                                       implementationName,
                                       implementationSpec,
                                       implementationKind),
                      emptyInterfaceList,
                      emptyMethodTypeList);
  }

  private static boolean containsString(List<String> values, String value) {
    for (String i: values) {
      if (i.equals(value)) {
        return true;
      }
    }

    return false;
  }

  private static void addInterface(List<String> interfaces, String name) {
    if (! containsString(interfaces, name)) {
      interfaces.add(name);
    }
  }

  private static byte[] makeLambda(String invokedName,
                                   MethodType invokedType,
                                   MethodType methodType,
                                   MethodHandle methodImplementation,
                                   Class[] interfaces,
                                   MethodType[] bridges)
  {
    String className;
    { int number;
      synchronized (LambdaMetafactory.class) {
        number = nextNumber++;
      }
      className = "Lambda-" + number;
    }

    List<PoolEntry> pool = new ArrayList();

    List<String> interfaceNames = new ArrayList();
    addInterface(interfaceNames, invokedType.returnType().getName().replace('.', '/'));
    for (Class i: interfaces) {
      addInterface(interfaceNames, i.getName().replace('.', '/'));
    }

    int[] interfaceIndexes = new int[interfaceNames.size()];
    for (int i = 0; i < interfaceNames.size(); ++i) {
      interfaceIndexes[i] = ConstantPool.addClass(pool, interfaceNames.get(i));
    }

    List<FieldData> fieldTable = new ArrayList();

    for (MethodType.Parameter p: invokedType.parameters()) {
      fieldTable.add
        (new FieldData(0,
                       ConstantPool.addUtf8(pool, "field" + p.index()),
                       ConstantPool.addUtf8(pool, p.spec())));
    }

    String constructorSpec = constructorSpec(invokedType);

    List<MethodData> methodTable = new ArrayList();
    List<String> invocationSpecs = new ArrayList();

    try {
      methodTable.add
        (new MethodData
         (Modifier.PUBLIC | Modifier.STATIC,
          ConstantPool.addUtf8(pool, "make"),
          ConstantPool.addUtf8(pool, invokedType.toMethodDescriptorString()),
          makeFactoryCode(pool, className, constructorSpec, invokedType)));

      methodTable.add
        (new MethodData
         (Modifier.PUBLIC,
          ConstantPool.addUtf8(pool, "<init>"),
          ConstantPool.addUtf8(pool, constructorSpec),
          makeConstructorCode(pool, className, invokedType)));

      String methodSpec = methodType.toMethodDescriptorString();
      methodTable.add
        (new MethodData
         (Modifier.PUBLIC,
          ConstantPool.addUtf8(pool, invokedName),
          ConstantPool.addUtf8(pool, methodSpec),
          makeInvocationCode(pool, className, constructorSpec, invokedType,
                             methodType, methodImplementation)));
      invocationSpecs.add(methodSpec);

      for (MethodType bridge: bridges) {
        String spec = bridge.toMethodDescriptorString();
        if (! containsString(invocationSpecs, spec)) {
          methodTable.add
            (new MethodData
             (Modifier.PUBLIC | 0x0040,
              ConstantPool.addUtf8(pool, invokedName),
              ConstantPool.addUtf8(pool, spec),
              makeInvocationCode(pool, className, constructorSpec, invokedType,
                                 bridge, methodImplementation)));
          invocationSpecs.add(spec);
        }
      }
    } catch (IOException e) {
      AssertionError error = new AssertionError();
      error.initCause(e);
      throw error;
    }

    int nameIndex = ConstantPool.addClass(pool, className);
    int superIndex = ConstantPool.addClass(pool, "java/lang/Object");

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    try {
      Assembler.writeClass
        (out, pool, nameIndex, superIndex, interfaceIndexes,
         fieldTable.toArray(new FieldData[fieldTable.size()]),
         methodTable.toArray(new MethodData[methodTable.size()]));
    } catch (IOException e) {
      AssertionError error = new AssertionError();
      error.initCause(e);
      throw error;
    }

    return out.toByteArray();
  }

  private static CallSite makeCallSite(MethodType invokedType, byte[] classData) throws AssertionError {
    try {
      return new ConstantCallSite
              (new MethodHandle
                      (MethodHandle.REF_invokeStatic, invokedType.loader, Classes.toVMMethod
                              (avata.SystemClassLoader.getClass
                                      (avata.Classes.defineVMClass
                                              (invokedType.loader, classData, 0, classData.length))
                                      .getMethod("make", invokedType.parameterArray()))));
    } catch (NoSuchMethodException e) {
      AssertionError error = new AssertionError();
      error.initCause(e);
      throw error;
    }
  }

  private static final Class[] emptyInterfaceList = new Class[] {};
  private static final MethodType[] emptyMethodTypeList = new MethodType[] {};

  public static CallSite metafactory(MethodHandles.Lookup caller,
                                     String invokedName,
                                     MethodType invokedType,
                                     MethodType methodType,
                                     MethodHandle methodImplementation,
                                     MethodType instantiatedMethodType)
    throws LambdaConversionException
  {
    byte[] classData = makeLambda(invokedName,
                                  invokedType,
                                  methodType,
                                  methodImplementation,
                                  emptyInterfaceList,
                                  emptyMethodTypeList);
    return makeCallSite(invokedType, classData);
  }

  public static CallSite altMetafactory(MethodHandles.Lookup caller,
                                        String invokedName,
                                        MethodType invokedType,
                                        Object... args) throws LambdaConversionException {
    // See openjdk8/jdk/src/share/classes/java/lang/invoke/LambdaMetafactory.java
    // Behaves as if the prototype is like this:
    //
    // CallSite altMetafactory(
    //    MethodHandles.Lookup caller,
    //    String invokedName,
    //    MethodType invokedType,
    //    MethodType methodType,
    //    MethodHandle methodImplementation,
    //    MethodType instantiatedMethodType,
    //    int flags,
    //    int markerInterfaceCount,  // IF flags has MARKERS set
    //    Class... markerInterfaces, // IF flags has MARKERS set
    //    int bridgeCount,           // IF flags has BRIDGES set
    //    MethodType... bridges      // IF flags has BRIDGES set
    //  )
    MethodType methodType = (MethodType) args[0];
    MethodHandle methodImplementation = (MethodHandle) args[1];

    int flags = (Integer) args[3];
    int argIndex = 4;

    Class[] interfaces;
    if ((flags & FLAG_MARKERS) != 0) {
      int markerCount = (Integer) args[argIndex++];
      interfaces = new Class[markerCount];
      for (int i = 0; i < markerCount; ++i) {
        interfaces[i] = (Class) args[argIndex++];
      }
    } else {
      interfaces = emptyInterfaceList;
    }

    MethodType[] bridges;
    if ((flags & FLAG_BRIDGES) != 0) {
      int bridgeCount = (Integer) args[argIndex++];
      bridges = new MethodType[bridgeCount];
      for (int i = 0; i < bridgeCount; ++i) {
        bridges[i] = (MethodType) args[argIndex++];
      }
    } else {
      bridges = emptyMethodTypeList;
    }

    if ((flags & FLAG_SERIALIZABLE) != 0) {
      boolean foundSerializableSupertype
        = java.io.Serializable.class.isAssignableFrom(invokedType.returnType());
      for (Class i: interfaces) {
        foundSerializableSupertype
          = foundSerializableSupertype
          || java.io.Serializable.class.isAssignableFrom(i);
      }

      if (! foundSerializableSupertype) {
        interfaces = Arrays.copyOf(interfaces, interfaces.length + 1);
        interfaces[interfaces.length - 1] = java.io.Serializable.class;
      }
    }

    byte[] classData = makeLambda(invokedName,
                                  invokedType,
                                  methodType,
                                  methodImplementation,
                                  interfaces,
                                  bridges);
    return makeCallSite(invokedType, classData);
  }
}
