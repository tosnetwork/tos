/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.lang.reflect;

import avata.Classes;
import avata.VMMethod;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.LinkedList;
import java.util.Map;
import java.util.TreeMap;

public class SignatureParser {
  private final ClassLoader loader;
  private final char[] array;
  private final String signature;
  private int offset;
  private final Type type;
  private final Map<String, TypeVariable> typeVariables;

  public static Type parse(ClassLoader loader, String signature, Class declaringClass) {
    return new SignatureParser(loader, signature, collectTypeVariables(declaringClass)).type;
  }

  public static TypeVariable<?>[] parseTypeParameters(Class declaringClass) {
    Map<String, TypeVariable> variables
      = collectTypeVariables(declaringClass.getDeclaringClass());
    return parseTypeParameters(declaringClass, variables, false);
  }

  public static TypeVariable<?>[] parseTypeParameters(Method method) {
    String signature = methodSignature(method.vmMethod);
    if (signature == null || signature.length() == 0 || signature.charAt(0) != '<') {
      return new TypeVariable<?>[0];
    }

    Map<String, TypeVariable> variables
      = collectTypeVariables(method.getDeclaringClass());
    return parseTypeParameters
      (method, method.vmMethod.class_.loader, signature, variables, false);
  }

  public static TypeVariable<?>[] parseTypeParameters(Constructor constructor) {
    VMMethod vmMethod = constructor.vmMethod();
    String signature = methodSignature(vmMethod);
    if (signature == null || signature.length() == 0 || signature.charAt(0) != '<') {
      return new TypeVariable<?>[0];
    }

    Map<String, TypeVariable> variables
      = collectTypeVariables(constructor.getDeclaringClass());
    return parseTypeParameters
      (constructor, vmMethod.class_.loader, signature, variables, false);
  }

  public static Type parseMethodReturnType(Method method) {
    String signature = methodSignature(method.vmMethod);
    if (signature == null) {
      return method.getReturnType();
    }

    Map<String, TypeVariable> variables = collectMethodTypeVariables(method);
    int offset = skipMethodParameters(signature);
    if (signature.charAt(offset) == 'V') {
      return Void.TYPE;
    }
    int end = scanTypeSignature(signature.toCharArray(), offset);
    return SignatureParser.parse
      (method.vmMethod.class_.loader, signature.substring(offset, end), variables);
  }

  public static Type[] parseMethodParameterTypes(Method method) {
    String signature = methodSignature(method.vmMethod);
    if (signature == null) {
      return method.getParameterTypes();
    }

    return parseMethodParameterTypes
      (method.vmMethod.class_.loader, signature, collectMethodTypeVariables(method));
  }

  public static Type[] parseMethodExceptionTypes(Method method) {
    String signature = methodSignature(method.vmMethod);
    if (signature == null || !hasMethodExceptionTypes(signature)) {
      return method.getExceptionTypes();
    }

    return parseMethodExceptionTypes
      (method.vmMethod.class_.loader, signature, collectMethodTypeVariables(method));
  }

  public static Type[] parseConstructorParameterTypes(Constructor constructor) {
    VMMethod vmMethod = constructor.vmMethod();
    String signature = methodSignature(vmMethod);
    if (signature == null) {
      return constructor.getParameterTypes();
    }

    return parseMethodParameterTypes
      (vmMethod.class_.loader, signature, collectMethodTypeVariables(constructor));
  }

  public static Type[] parseConstructorExceptionTypes(Constructor constructor) {
    VMMethod vmMethod = constructor.vmMethod();
    String signature = methodSignature(vmMethod);
    if (signature == null || !hasMethodExceptionTypes(signature)) {
      return constructor.getExceptionTypes();
    }

    return parseMethodExceptionTypes
      (vmMethod.class_.loader, signature, collectMethodTypeVariables(constructor));
  }

  private static Type parse(ClassLoader loader, String signature, Map<String, TypeVariable> typeVariables) {
    return new SignatureParser(loader, signature, typeVariables).type;
  }

  private SignatureParser(ClassLoader loader, String signature, Map<String, TypeVariable> typeVariables) {
    this.loader = loader;
    this.signature = signature;
    array = signature.toCharArray();
    this.typeVariables = typeVariables;
    type = parseType();
    if (offset != array.length) {
      throw new IllegalArgumentException("Extra characters after " + offset
          + ": " + signature);
    }
  }

  private Type parseType() {
    char c = array[offset++];
    if (c == 'B') {
      return Byte.TYPE;
    } else if (c == 'C') {
      return Character.TYPE;
    } else if (c == 'D') {
      return Double.TYPE;
    } else if (c == 'F') {
      return Float.TYPE;
    } else if (c == 'I') {
      return Integer.TYPE;
    } else if (c == 'J') {
      return Long.TYPE;
    } else if (c == 'S') {
      return Short.TYPE;
    } else if (c == 'Z') {
      return Boolean.TYPE;
    } else if (c == 'T') {
      int end = signature.indexOf(';', offset);
      if (end < 0) {
        throw new RuntimeException("No semicolon found while parsing signature");
      }
      String name = new String(array, offset, end - offset);
      Type res = typeVariables.get(name);
      if (res == null) {
        throw new IllegalArgumentException("Unknown type variable: " + name);
      }
      offset = end + 1;
      return res;
    } else if (c == '[') {
      return parseArrayType();
    } else if (c != 'L') {
      throw new IllegalArgumentException("Unexpected character: " + c + ", signature: " + new String(array, 0, array.length) + ", i = " + offset);
    }
    StringBuilder builder = new StringBuilder();
    Type ownerType = null;
    for (;;) {
      for (;;) {
        c = array[offset++];
        if (c == ';' || c == '<') {
          break;
        }
        builder.append(c == '/' ? '.' : c);
      }
      String rawTypeName = builder.toString();
      Class<?> rawType;
      try {
        rawType = loader.loadClass(rawTypeName);
      } catch (ClassNotFoundException e) {
        throw new RuntimeException("Could not find class " + rawTypeName);
      }

      int lastDollar = rawTypeName.lastIndexOf('$');
      if (lastDollar != -1 && ownerType == null) {
        String ownerName = rawTypeName.substring(0, lastDollar);
        try {
          ownerType = loader.loadClass(ownerName);
        } catch (ClassNotFoundException e) {
          throw new RuntimeException("Could not find class " + ownerName);
        }
      }

      if (c == ';') {
        return rawType;
      }
      List<Type> args = new ArrayList<Type>();
      while (array[offset] != '>') {
        args.add(parseTypeArgument());
      }
      ++offset;
      c = array[offset++];
      ParameterizedType type = makeType(args.toArray(new Type[args.size()]), ownerType, rawType);
      if (c == ';') {
        return type;
      }
      if (c != '.') {
        throw new IllegalArgumentException
          ("Unexpected character after parameterized type: " + c);
      }
      ownerType = type;
      builder.append("$");
    }
  }

  private Type parseArrayType() {
    int start = offset - 1;
    Type component = parseType();
    if (component instanceof Class) {
      String name = new String(array, start, offset - start).replace('/', '.');
      return Classes.forCanonicalName(loader, name);
    }
    return makeArrayType(component);
  }

  private Type parseTypeArgument() {
    char c = array[offset];
    if (c == '*') {
      offset++;
      return makeWildcard(new Type[] { Object.class }, new Type[0]);
    } else if (c == '+') {
      offset++;
      return makeWildcard(new Type[] { parseType() }, new Type[0]);
    } else if (c == '-') {
      offset++;
      return makeWildcard(new Type[] { Object.class }, new Type[] { parseType() });
    } else {
      return parseType();
    }
  }

  private static String typeName(Type type) {
    if (type instanceof Class) {
      Class<?> clazz = (Class<?>) type;
      if (clazz.isArray()) {
        return clazz.getCanonicalName();
      }
      return clazz.getName();
    }
    return type.toString();
  }

  private static ParameterizedType makeType(final Type[] args, final Type owner, final Type raw) {
    return new ParameterizedType() {
      private final Type[] arguments = (Type[]) args.clone();

      @Override
        public Type getRawType() {
          return raw;
        }

      @Override
        public Type getOwnerType() {
          return owner;
        }

      @Override
        public Type[] getActualTypeArguments() {
          return (Type[]) arguments.clone();
        }

      @Override
        public boolean equals(Object other) {
          if (other instanceof ParameterizedType) {
            ParameterizedType that = (ParameterizedType) other;
            return equal(owner, that.getOwnerType())
              && equal(raw, that.getRawType())
              && Arrays.equals(arguments, that.getActualTypeArguments());
          }
          return false;
        }

      @Override
        public int hashCode() {
          return Arrays.hashCode(arguments) ^ objectHashCode(owner)
            ^ objectHashCode(raw);
        }

      @Override
        public String toString() {
          StringBuilder builder = new StringBuilder();
          if (owner != null && raw instanceof Class) {
            Class rawClass = (Class) raw;
            builder.append(typeName(owner));
            builder.append('$');
            if (owner instanceof ParameterizedType) {
              Type ownerRaw = ((ParameterizedType) owner).getRawType();
              if (ownerRaw instanceof Class) {
                String prefix = ((Class) ownerRaw).getName() + "$";
                String rawName = rawClass.getName();
                if (rawName.startsWith(prefix)) {
                  builder.append(rawName.substring(prefix.length()));
                } else {
                  builder.append(rawClass.getSimpleName());
                }
              } else {
                builder.append(rawClass.getSimpleName());
              }
            } else {
              builder.append(rawClass.getSimpleName());
            }
          } else {
            builder.append(typeName(raw));
          }
          if (arguments.length > 0) {
            builder.append('<');
            String sep = "";
            for (Type t : arguments) {
              builder.append(sep).append(typeName(t));
              sep = ", ";
            }
            builder.append('>');
          }
          return builder.toString();
        }
    };
  }

  private static GenericArrayType makeArrayType(final Type component) {
    return new GenericArrayType() {
      @Override
        public Type getGenericComponentType() {
          return component;
        }

      @Override
        public boolean equals(Object other) {
          if (other instanceof GenericArrayType) {
            GenericArrayType that = (GenericArrayType) other;
            return equal(component, that.getGenericComponentType());
          }
          return false;
        }

      @Override
        public int hashCode() {
          return objectHashCode(component);
        }

      @Override
        public String toString() {
          return typeName(component) + "[]";
        }
    };
  }

  private static WildcardType makeWildcard(final Type[] uppers, final Type[] lowers) {
    return new WildcardType() {
      private final Type[] upperBounds = (Type[]) uppers.clone();
      private final Type[] lowerBounds = (Type[]) lowers.clone();

      @Override
        public Type[] getUpperBounds() {
          return (Type[]) upperBounds.clone();
        }

      @Override
        public Type[] getLowerBounds() {
          return (Type[]) lowerBounds.clone();
        }

      @Override
        public boolean equals(Object other) {
          if (other instanceof WildcardType) {
            WildcardType that = (WildcardType) other;
            return Arrays.equals(lowerBounds, that.getLowerBounds())
              && Arrays.equals(upperBounds, that.getUpperBounds());
          }
          return false;
        }

      @Override
        public int hashCode() {
          return Arrays.hashCode(lowerBounds) ^ Arrays.hashCode(upperBounds);
        }

      @Override
        public String toString() {
          Type[] bounds = lowerBounds;
          String prefix = "? super ";
          if (lowerBounds.length == 0) {
            if (upperBounds.length == 0
                || (upperBounds.length == 1 && Object.class.equals(upperBounds[0]))) {
              return "?";
            }
            bounds = upperBounds;
            prefix = "? extends ";
          }
          StringBuilder builder = new StringBuilder(prefix);
          String sep = "";
          for (Type t : bounds) {
            builder.append(sep).append(typeName(t));
            sep = " & ";
          }
          return builder.toString();
        }
    };
  }

  private static boolean equal(Object a, Object b) {
    return a == b || (a != null && a.equals(b));
  }

  private static int objectHashCode(Object o) {
    return o == null ? 0 : o.hashCode();
  }
  
  private static Map<String, TypeVariable> collectTypeVariables(Class clz) {
    Map<String, TypeVariable> varsMap = new TreeMap<String, TypeVariable>();
    LinkedList<Class> classList = new LinkedList<Class>();
    for (Class c = clz; c != null; c = c.getDeclaringClass()) {
      classList.addFirst(c);
    }
    
    for (Class cur : classList) {
      parseTypeParameters(cur, varsMap, true);
    };
    return varsMap;
  }

  private static Map<String, TypeVariable> collectMethodTypeVariables
    (Method method)
  {
    Map<String, TypeVariable> variables
      = collectTypeVariables(method.getDeclaringClass());
    String signature = methodSignature(method.vmMethod);
    if (signature != null && signature.length() > 0 && signature.charAt(0) == '<') {
      parseTypeParameters
        (method, method.vmMethod.class_.loader, signature, variables, false);
    }
    return variables;
  }

  private static Map<String, TypeVariable> collectMethodTypeVariables
    (Constructor constructor)
  {
    VMMethod vmMethod = constructor.vmMethod();
    Map<String, TypeVariable> variables
      = collectTypeVariables(constructor.getDeclaringClass());
    String signature = methodSignature(vmMethod);
    if (signature != null && signature.length() > 0 && signature.charAt(0) == '<') {
      parseTypeParameters(constructor, vmMethod.class_.loader, signature, variables, false);
    }
    return variables;
  }

  private static String methodSignature(VMMethod method) {
    if (method.addendum == null || method.addendum.signature == null) {
      return null;
    }
    return Classes.toString((byte[]) method.addendum.signature);
  }

  private static TypeVariable<?>[] parseTypeParameters
    (Class declaringClass, Map<String, TypeVariable> variables, boolean store)
  {
    if (declaringClass == null
        || declaringClass.vmClass.addendum == null
        || declaringClass.vmClass.addendum.signature == null) {
      return new TypeVariable<?>[0];
    }

    String signature = Classes.toString((byte[]) declaringClass.vmClass.addendum.signature);
    final char[] signChars = signature.toCharArray();
    if (signChars.length == 0 || signChars[0] != '<') {
      return new TypeVariable<?>[0];
    }

    LinkedList<TypeVariableImpl> varsList = new LinkedList<TypeVariableImpl>();
    try {
      int i = 1;
      while (signChars[i] != '>') {
        final int colon = signature.indexOf(':', i);
        if (colon < 0 || colon + 1 >= signChars.length) {
          throw new RuntimeException("Can't find ':' in the signature "
                                     + signature + " starting from " + i);
        }

        String typeVarName = new String(signChars, i, colon - i);
        i = colon + 1;

        ArrayList<Type> bounds = new ArrayList<Type>();
        if (signChars[i] != ':') {
          int end = scanTypeSignature(signChars, i);
          bounds.add(SignatureParser.parse
                     (declaringClass.vmClass.loader,
                      new String(signChars, i, end - i),
                      variables));
          i = end;
        }

        while (signChars[i] == ':') {
          i++;
          int end = scanTypeSignature(signChars, i);
          bounds.add(SignatureParser.parse
                     (declaringClass.vmClass.loader,
                      new String(signChars, i, end - i),
                      variables));
          i = end;
        }

        if (bounds.isEmpty()) {
          bounds.add(Object.class);
        }

        TypeVariableImpl tv = new TypeVariableImpl
          (declaringClass, typeVarName, bounds.toArray(new Type[bounds.size()]));
        varsList.add(tv);
        variables.put(typeVarName, tv);
      }
    } catch (IndexOutOfBoundsException e) {
      throw new RuntimeException("Signature of " + declaringClass + " is broken ("
                                 + signature + ") and can't be parsed", e);
    }

    for (TypeVariableImpl tv : varsList) {
      if (store) {
        variables.put(tv.getName(), tv);
      }
    }

    return varsList.toArray(new TypeVariable<?>[varsList.size()]);
  }

  private static TypeVariable<?>[] parseTypeParameters
    (GenericDeclaration declaration, ClassLoader loader, String signature,
     Map<String, TypeVariable> variables, boolean store)
  {
    final char[] signChars = signature.toCharArray();
    if (signChars.length == 0 || signChars[0] != '<') {
      return new TypeVariable<?>[0];
    }

    LinkedList<TypeVariableImpl> varsList = new LinkedList<TypeVariableImpl>();
    try {
      parseTypeParameters
        (declaration, loader, signature, signChars, variables, varsList);
    } catch (IndexOutOfBoundsException e) {
      throw new RuntimeException("Signature of " + declaration + " is broken ("
                                 + signature + ") and can't be parsed", e);
    }

    for (TypeVariableImpl tv : varsList) {
      if (store) {
        variables.put(tv.getName(), tv);
      }
    }

    return varsList.toArray(new TypeVariable<?>[varsList.size()]);
  }

  private static int parseTypeParameters
    (GenericDeclaration declaration, ClassLoader loader, String signature,
     char[] signChars, Map<String, TypeVariable> variables,
     LinkedList<TypeVariableImpl> varsList)
  {
    int i = 1;
    while (signChars[i] != '>') {
      final int colon = signature.indexOf(':', i);
      if (colon < 0 || colon + 1 >= signChars.length) {
        throw new RuntimeException("Can't find ':' in the signature "
                                   + signature + " starting from " + i);
      }

      String typeVarName = new String(signChars, i, colon - i);
      i = colon + 1;

      ArrayList<Type> bounds = new ArrayList<Type>();
      if (signChars[i] != ':') {
        int end = scanTypeSignature(signChars, i);
        bounds.add(SignatureParser.parse
                   (loader, new String(signChars, i, end - i), variables));
        i = end;
      }

      while (signChars[i] == ':') {
        i++;
        int end = scanTypeSignature(signChars, i);
        bounds.add(SignatureParser.parse
                   (loader, new String(signChars, i, end - i), variables));
        i = end;
      }

      if (bounds.isEmpty()) {
        bounds.add(Object.class);
      }

      TypeVariableImpl tv = new TypeVariableImpl
        (declaration, typeVarName, bounds.toArray(new Type[bounds.size()]));
      varsList.add(tv);
      variables.put(typeVarName, tv);
    }

    return i + 1;
  }

  private static int skipTypeParameters(String signature) {
    if (signature.length() == 0 || signature.charAt(0) != '<') {
      return 0;
    }

    int depth = 0;
    for (int i = 0; i < signature.length(); ++i) {
      char c = signature.charAt(i);
      if (c == '<') {
        depth++;
      } else if (c == '>') {
        depth--;
        if (depth == 0) {
          return i + 1;
        }
      }
    }

    throw new IllegalArgumentException("Bad formal type parameters: " + signature);
  }

  private static int skipMethodParameters(String signature) {
    char[] signChars = signature.toCharArray();
    int offset = skipTypeParameters(signature);
    if (signChars[offset] != '(') {
      throw new IllegalArgumentException("Bad method signature: " + signature);
    }

    offset++;
    while (signChars[offset] != ')') {
      offset = scanTypeSignature(signChars, offset);
    }
    return offset + 1;
  }

  private static Type[] parseMethodParameterTypes
    (ClassLoader loader, String signature, Map<String, TypeVariable> variables)
  {
    char[] signChars = signature.toCharArray();
    int offset = skipTypeParameters(signature);
    if (signChars[offset] != '(') {
      throw new IllegalArgumentException("Bad method signature: " + signature);
    }

    offset++;
    ArrayList<Type> types = new ArrayList<Type>();
    while (signChars[offset] != ')') {
      int end = scanTypeSignature(signChars, offset);
      types.add(SignatureParser.parse
                (loader, new String(signChars, offset, end - offset), variables));
      offset = end;
    }
    return types.toArray(new Type[types.size()]);
  }

  private static Type[] parseMethodExceptionTypes
    (ClassLoader loader, String signature, Map<String, TypeVariable> variables)
  {
    char[] signChars = signature.toCharArray();
    int offset = skipMethodParameters(signature);
    if (signChars[offset] == 'V') {
      offset++;
    } else {
      offset = scanTypeSignature(signChars, offset);
    }

    ArrayList<Type> types = new ArrayList<Type>();
    while (offset < signChars.length) {
      if (signChars[offset] != '^') {
        throw new IllegalArgumentException("Bad throws signature: " + signature);
      }
      offset++;
      int end = scanTypeSignature(signChars, offset);
      types.add(SignatureParser.parse
                (loader, new String(signChars, offset, end - offset), variables));
      offset = end;
    }
    return types.toArray(new Type[types.size()]);
  }

  private static boolean hasMethodExceptionTypes(String signature) {
    char[] signChars = signature.toCharArray();
    int offset = skipMethodParameters(signature);
    if (signChars[offset] == 'V') {
      offset++;
    } else {
      offset = scanTypeSignature(signChars, offset);
    }
    return offset < signChars.length;
  }

  private static int scanTypeSignature(char[] signature, int offset) {
    char c = signature[offset];
    if (c == 'L') {
      int angles = 0;
      for (int i = offset + 1; i < signature.length; ++i) {
        if (signature[i] == '<') {
          angles++;
        } else if (signature[i] == '>') {
          angles--;
        } else if (signature[i] == ';' && angles == 0) {
          return i + 1;
        }
      }
    } else if (c == 'T') {
      for (int i = offset + 1; i < signature.length; ++i) {
        if (signature[i] == ';') {
          return i + 1;
        }
      }
    } else if (c == '[') {
      do {
        offset++;
      } while (signature[offset] == '[');
      return scanTypeSignature(signature, offset);
    } else if ("BCDFIJSZV".indexOf(c) >= 0) {
      return offset + 1;
    }

    throw new IllegalArgumentException("Bad type signature at " + offset);
  }

  private static class TypeVariableImpl implements TypeVariable {
    private String name;
    private GenericDeclaration declaration;
    private Type[] bounds;

    public Type[] getBounds() {
      return (Type[]) bounds.clone();
    }
    
    public GenericDeclaration getGenericDeclaration() {
      return declaration;
    }
    
    public String getName() {
      return name;
    }
    
    TypeVariableImpl(GenericDeclaration declaration, String name, Type[] bounds) {
      this.declaration = declaration;
      this.name = name;
      this.bounds = bounds;
    }
    
    @Override
    public boolean equals(Object other) {
      if (other instanceof TypeVariable) {
        TypeVariable that = (TypeVariable) other;
        return name.equals(that.getName())
          && declaration.equals(that.getGenericDeclaration());
      }
      return false;
    }

    @Override
    public int hashCode() {
      return declaration.hashCode() ^ name.hashCode();
    }

    @Override
    public String toString() {
      return name;
    }
  }
}
