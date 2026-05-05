import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Constructor;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.lang.reflect.TypeVariable;
import java.lang.reflect.GenericArrayType;
import java.lang.reflect.WildcardType;
import java.lang.reflect.InvocationTargetException;

public class Reflection {
  public static boolean booleanMethod() {
    return true;
  }

  public static byte byteMethod() {
    return 1;
  }

  public static char charMethod() {
    return '2';
  }

  public static short shortMethod() {
    return 3;
  }

  public static int intMethod() {
    return 4;
  }

  public static float floatMethod() {
    return 5.0f;
  }

  public static long longMethod() {
    return 6;
  }

  public static double doubleMethod() {
    return 7.0;
  }

  public static void expect(boolean v) {
    if (! v) throw new RuntimeException();
  }

  private static class Hello<T> {
    private class World<S> { }
  }

  private static class GenericBounds<T extends Number & Runnable, U, V extends T> {
  }

  private static void innerClasses() throws Exception {
    Class c = Reflection.class;
    Class[] inner = c.getDeclaredClasses();
    expect(4 == inner.length);
    boolean foundHello = false;
    for (int i = 0; i < inner.length; ++i) {
      foundHello |= Hello.class == inner[i];
    }
    expect(foundHello);
  }

  private int egads;

  private static void annotations() throws Exception {
    Field egads = Reflection.class.getDeclaredField("egads");
    expect(egads.getAnnotation(Deprecated.class) == null);
  }

  private Integer[] array;

  private Integer integer;

  public static Hello<Hello<Reflection>>.World<Hello<String>> pinky;

  private static void genericType() throws Exception {
    Field field = Reflection.class.getDeclaredField("egads");
    expect(field.getGenericType() == Integer.TYPE);

    field = Reflection.class.getField("pinky");
    expect("Reflection$Hello$World".equals(field.getType().getName()));
    expect(field.getGenericType() instanceof ParameterizedType);
    ParameterizedType type = (ParameterizedType) field.getGenericType();

    expect(type.getRawType() instanceof Class);
    Class<?> clazz = (Class<?>) type.getRawType();
    expect("Reflection$Hello$World".equals(clazz.getName()));

    expect(type.getOwnerType() instanceof ParameterizedType);
    ParameterizedType owner = (ParameterizedType) type.getOwnerType();
    clazz = (Class<?>) owner.getRawType();
    expect(clazz == Hello.class);

    Type[] args = type.getActualTypeArguments();
    expect(1 == args.length);
    expect(args[0] instanceof ParameterizedType);

    ParameterizedType arg = (ParameterizedType) args[0];
    expect(arg.getRawType() instanceof Class);
    clazz = (Class<?>) arg.getRawType();
    expect("Reflection$Hello".equals(clazz.getName()));

    args = arg.getActualTypeArguments();
    expect(1 == args.length);
    expect(args[0] == String.class);

    Type[] copy = arg.getActualTypeArguments();
    copy[0] = Object.class;
    expect(arg.getActualTypeArguments()[0] == String.class);

    ParameterizedType sameType = (ParameterizedType) field.getGenericType();
    expect(type.equals((ParameterizedType) sameType));
    expect(type.hashCode() == sameType.hashCode());

    expect(Reflection.class.getTypeParameters().length == 0);
    expect(Integer.TYPE.getTypeParameters().length == 0);

    TypeVariable[] vars = GenericBounds.class.getTypeParameters();
    expect(3 == vars.length);
    expect("T".equals(vars[0].getName()));
    expect(vars[0].getGenericDeclaration() == GenericBounds.class);
    Type[] bounds = vars[0].getBounds();
    expect(2 == bounds.length);
    expect(bounds[0] == Number.class);
    expect(bounds[1] == Runnable.class);

    bounds[0] = String.class;
    expect(vars[0].getBounds()[0] == Number.class);

    expect("U".equals(vars[1].getName()));
    bounds = vars[1].getBounds();
    expect(1 == bounds.length);
    expect(bounds[0] == Object.class);

    expect("V".equals(vars[2].getName()));
    bounds = vars[2].getBounds();
    expect(1 == bounds.length);
    expect(bounds[0] == vars[0]);
    expect(vars[0].equals(GenericBounds.class.getTypeParameters()[0]));

    Method generic = Reflection.class.getMethod
      ("genericMethod", Number.class, java.util.List.class);
    expect(generic.getParameterCount() == 2);

    TypeVariable[] methodVars = generic.getTypeParameters();
    expect(2 == methodVars.length);
    expect("T".equals(methodVars[0].getName()));
    expect(methodVars[0].getGenericDeclaration() == generic);
    bounds = methodVars[0].getBounds();
    expect(2 == bounds.length);
    expect(bounds[0] == Number.class);
    expect(bounds[1] == Runnable.class);
    expect("U".equals(methodVars[1].getName()));
    bounds = methodVars[1].getBounds();
    expect(1 == bounds.length);
    expect(bounds[0].equals(methodVars[0]));

    Type[] genericParameters = generic.getGenericParameterTypes();
    expect(2 == genericParameters.length);
    expect(genericParameters[0].equals(methodVars[0]));
    expect(genericParameters[1] instanceof ParameterizedType);
    type = (ParameterizedType) genericParameters[1];
    expect(type.getRawType() == java.util.List.class);
    args = type.getActualTypeArguments();
    expect(1 == args.length);
    expect(args[0] == String.class);

    expect(generic.getGenericReturnType().equals(methodVars[1]));
    Type[] genericExceptions = generic.getGenericExceptionTypes();
    expect(1 == genericExceptions.length);
    expect(genericExceptions[0] == java.io.IOException.class);
    expect(Reflection.class.getMethod("booleanMethod").getGenericReturnType()
           == Boolean.TYPE);

    Constructor constructor = GenericConstructor.class.getConstructor(Number.class);
    expect(constructor.getParameterCount() == 1);
    TypeVariable[] constructorVars = constructor.getTypeParameters();
    expect(1 == constructorVars.length);
    expect("T".equals(constructorVars[0].getName()));
    expect(constructorVars[0].getGenericDeclaration() == constructor);
    bounds = constructorVars[0].getBounds();
    expect(2 == bounds.length);
    expect(bounds[0] == Number.class);
    expect(bounds[1] == Runnable.class);
    genericParameters = constructor.getGenericParameterTypes();
    expect(1 == genericParameters.length);
    expect(genericParameters[0].equals(constructorVars[0]));
    genericExceptions = constructor.getGenericExceptionTypes();
    expect(1 == genericExceptions.length);
    expect(genericExceptions[0] == java.io.IOException.class);

    field = GenericTypes.class.getField("upperWildcard");
    type = (ParameterizedType) field.getGenericType();
    args = type.getActualTypeArguments();
    expect(1 == args.length);
    expect(args[0] instanceof WildcardType);
    WildcardType wildcard = (WildcardType) args[0];
    bounds = wildcard.getUpperBounds();
    expect(1 == bounds.length);
    expect(bounds[0] == Number.class);
    expect(0 == wildcard.getLowerBounds().length);
    bounds[0] = Object.class;
    expect(wildcard.getUpperBounds()[0] == Number.class);
    WildcardType sameWildcard = (WildcardType)
      ((ParameterizedType) field.getGenericType()).getActualTypeArguments()[0];
    expect(wildcard.equals(sameWildcard));
    expect(wildcard.hashCode() == sameWildcard.hashCode());

    field = GenericTypes.class.getField("lowerWildcard");
    wildcard = (WildcardType)
      ((ParameterizedType) field.getGenericType()).getActualTypeArguments()[0];
    bounds = wildcard.getUpperBounds();
    expect(1 == bounds.length);
    expect(bounds[0] == Object.class);
    bounds = wildcard.getLowerBounds();
    expect(1 == bounds.length);
    expect(bounds[0] == Integer.class);

    field = GenericTypes.class.getField("unboundedWildcard");
    wildcard = (WildcardType)
      ((ParameterizedType) field.getGenericType()).getActualTypeArguments()[0];
    bounds = wildcard.getUpperBounds();
    expect(1 == bounds.length);
    expect(bounds[0] == Object.class);
    expect(0 == wildcard.getLowerBounds().length);
    expect("?".equals(wildcard.toString()));

    field = GenericTypes.class.getField("typeVariableArray");
    expect(field.getGenericType() instanceof GenericArrayType);
    GenericArrayType arrayType = (GenericArrayType) field.getGenericType();
    expect(arrayType.getGenericComponentType().equals
           (GenericTypes.class.getTypeParameters()[0]));
    expect(arrayType.equals(field.getGenericType()));
    expect(arrayType.hashCode() == field.getGenericType().hashCode());

    field = GenericTypes.class.getField("parameterizedArray");
    arrayType = (GenericArrayType) field.getGenericType();
    expect(arrayType.getGenericComponentType() instanceof ParameterizedType);
    type = (ParameterizedType) arrayType.getGenericComponentType();
    expect(type.getRawType() == java.util.List.class);
    args = type.getActualTypeArguments();
    expect(1 == args.length);
    expect(args[0] == String.class);
  }

  public static void throwOOME() {
    throw new OutOfMemoryError();
  }

  public static void throwsChecked()
    throws java.io.IOException, IllegalStateException
  {
  }

  public static <T extends Number & Runnable, U extends T> U genericMethod
    (T value, java.util.List<String> names)
    throws java.io.IOException
  {
    return null;
  }

  private static void exceptionTypes() throws Exception {
    Class[] exceptions = Reflection.class.getMethod("booleanMethod")
      .getExceptionTypes();
    expect(exceptions.length == 0);

    exceptions = Reflection.class.getMethod("throwsChecked")
      .getExceptionTypes();
    expect(exceptions.length == 2);
    expect(exceptions[0] == java.io.IOException.class);
    expect(exceptions[1] == IllegalStateException.class);

    Constructor constructor = ThrowsConstructor.class.getConstructor();
    exceptions = constructor.getExceptionTypes();
    expect(exceptions.length == 2);
    expect(exceptions[0] == java.io.IOException.class);
    expect(exceptions[1] == IllegalArgumentException.class);
  }

  public static void classType() throws Exception {
    // Class types
    expect(!Reflection.class.isAnonymousClass());
    expect(!Reflection.class.isLocalClass());
    expect(!Reflection.class.isMemberClass());

    expect(Reflection.Hello.class.isMemberClass());

    Cloneable anonymousLocal = new Cloneable() {};
    expect(anonymousLocal.getClass().isAnonymousClass());

    class NamedLocal {}
    expect(NamedLocal.class.isLocalClass());
  }

  private static class MyClassLoader extends ClassLoader {
    public Package definePackage1(String name) {
      return definePackage(name, null, null, null, null, null, null, null);
    }
  }

  public static void main(String[] args) throws Exception {
    expect(new MyClassLoader().definePackage1("foo").getName().equals("foo"));

    innerClasses();
    annotations();
    genericType();
    classType();
    exceptionTypes();

    Class system = Class.forName("java.lang.System");
    Field out = system.getDeclaredField("out");
    Class output = Class.forName("java.io.PrintStream");
    Method println = output.getDeclaredMethod("println", String.class);

    println.invoke(out.get(null), "Hello, World!");

    expect((Boolean) Reflection.class.getMethod("booleanMethod").invoke(null));

    expect(1 == (Byte) Reflection.class.getMethod("byteMethod").invoke(null));

    expect('2' == (Character) Reflection.class.getMethod
           ("charMethod").invoke(null));

    expect(3 == (Short) Reflection.class.getMethod
           ("shortMethod").invoke(null));

    expect(4 == (Integer) Reflection.class.getMethod
           ("intMethod").invoke(null));

    expect(5.0 == (Float) Reflection.class.getMethod
           ("floatMethod").invoke(null));

    expect(6 == (Long) Reflection.class.getMethod
           ("longMethod").invoke(null));

    expect(7.0 == (Double) Reflection.class.getMethod
           ("doubleMethod").invoke(null));

    { Class[][] array = new Class[][] { { Class.class } };
      expect("[Ljava.lang.Class;".equals(array[0].getClass().getName()));
      expect(Class[].class == array[0].getClass());
      expect(array.getClass().getComponentType() == array[0].getClass());
    }

    { Reflection r = new Reflection();
      expect(r.egads == 0);

      Reflection.class.getDeclaredField("egads").set(r, (Integer)42);
      expect(((Integer)Reflection.class.getDeclaredField("egads").get(r)) == 42);

      Reflection.class.getDeclaredField("egads").setInt(r, 43);
      expect(Reflection.class.getDeclaredField("egads").getInt(r) == 43);

      Integer[] array = new Integer[0];
      Reflection.class.getDeclaredField("array").set(r, array);
      expect(Reflection.class.getDeclaredField("array").get(r) == array);

      try {
        Reflection.class.getDeclaredField("array").set(r, new Object());
        expect(false);
      } catch (IllegalArgumentException e) {
        // cool
      }

      Integer integer = 45;
      Reflection.class.getDeclaredField("integer").set(r, integer);
      expect(Reflection.class.getDeclaredField("integer").get(r) == integer);

      try {
        Reflection.class.getDeclaredField("integer").set(r, new Object());
        expect(false);
      } catch (IllegalArgumentException e) {
        // cool
      }

      try {
        Reflection.class.getDeclaredField("integer").set
          (new Object(), integer);
        expect(false);
      } catch (IllegalArgumentException e) {
        // cool
      }

      try {
        Reflection.class.getDeclaredField("integer").get(new Object());
        expect(false);
      } catch (IllegalArgumentException e) {
        // cool
      }
    }

    try {
      Foo.class.getMethod("foo").invoke(null);
      expect(false);
    } catch (ExceptionInInitializerError e) {
      expect(e.getCause() instanceof MyException);
    }

    try {
      Foo.class.getConstructor().newInstance();
      expect(false);
    } catch (NoClassDefFoundError e) {
      // cool
    }

    try {
      Foo.class.getField("foo").get(null);
      expect(false);
    } catch (NoClassDefFoundError e) {
      // cool
    }

    try {
      Foo.class.getField("foo").set(null, (Integer)42);
      expect(false);
    } catch (NoClassDefFoundError e) {
      // cool
    }

    try {
      Foo.class.getField("foo").set(null, new Object());
      expect(false);
    } catch (IllegalArgumentException e) {
      // cool
    } catch (NoClassDefFoundError e) {
      // cool
    }

    { Method m = Reflection.class.getMethod("throwOOME");
      try {
        m.invoke(null);
      } catch(Throwable t) {
        expect(t.getClass() == InvocationTargetException.class);
      }
    }

    expect((Foo.class.getMethod("toString").getModifiers()
            & Modifier.PUBLIC) != 0);

    expect(avata.TestReflection.get(Baz.class.getField("foo"), new Baz())
           .equals(42));
    expect((Baz.class.getModifiers() & Modifier.PUBLIC) == 0);

    expect(B.class.getDeclaredMethods().length == 0);

    new Runnable() {
      public void run() {
        expect(getClass().getDeclaringClass() == null);
      }
    }.run();

    expect(avata.testing.annotations.Test.class.getPackage().getName().equals
           ("avata.testing.annotations"));

    expect(Baz.class.getField("foo").getAnnotation(Ann.class) == null);
    expect(Baz.class.getField("foo").getAnnotations().length == 0);

    expect(new Runnable() { public void run() { } }.getClass()
           .getEnclosingClass().equals(Reflection.class));

    expect(new Runnable() { public void run() { } }.getClass()
           .getEnclosingMethod().equals
           (Reflection.class.getMethod
            ("main", new Class[] { String[].class })));

    Slithy.class.getMethod("tove", Gybe.class);

    try {
      Slithy.class.getMethod("tove", Bandersnatch.class);
      expect(false);
    } catch (NoSuchMethodException e) {
      // cool
    }

    expect(C.class.getInterfaces().length == 1);
    expect(C.class.getInterfaces()[0].equals(B.class));
  }

  protected static class Baz {
    public int foo = 42;
  }
}

class Bandersnatch { }

class Gybe extends Bandersnatch { }

class ThrowsConstructor {
  public ThrowsConstructor()
    throws java.io.IOException, IllegalArgumentException
  {
  }
}

class GenericConstructor {
  public <T extends Number & Runnable> GenericConstructor(T value)
    throws java.io.IOException
  {
  }
}

class GenericTypes<T> {
  public java.util.List<? extends Number> upperWildcard;
  public java.util.List<? super Integer> lowerWildcard;
  public java.util.List<?> unboundedWildcard;
  public T[] typeVariableArray;
  public java.util.List<String>[] parameterizedArray;
}

class Slithy {
  public static void tove(Gybe gybe) {
    // ignore
  }
}

class Foo {
  static {
    if (true) throw new MyException();
  }

  public Foo() { }

  public static int foo;

  public static void foo() {
    // ignore
  }
}

class MyException extends RuntimeException { }

interface A {
  void foo();
}

interface B extends A { }

class C implements B {
  public void foo() { }
}

@interface Ann { }
