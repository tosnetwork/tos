/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.lang.reflect;

import avata.Classes;

import java.util.ArrayList;
import java.util.List;
import java.util.LinkedList;
import java.util.Map;
import java.util.HashMap;

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
        args.add(parseType());
      }
      ++offset;
      c = array[offset++];
      ParameterizedType type = makeType(args.toArray(new Type[args.size()]), ownerType, rawType);
      if (c == ';') {
        return type;
      }
      if (c != '.') {
        throw new RuntimeException("TODO");
      }
      ownerType = type;
      builder.append("$");
    }
  }

  private static String typeName(Type type) {
    if (type instanceof Class) {
      Class<?> clazz = (Class<?>) type;
      return clazz.getName();
    }
    return type.toString();
  }

  private static ParameterizedType makeType(final Type[] args, final Type owner, final Type raw) {
    return new ParameterizedType() {
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
          return args;
        }

      @Override
        public String toString() {
          StringBuilder builder = new StringBuilder();
          builder.append(typeName(raw));
          builder.append('<');
          String sep = "";
          for (Type t : args) {
            builder.append(sep).append(typeName(t));
            sep = ", ";
          }
          builder.append('>');
          return builder.toString();
        }
    };
  }
  
  private static Map<String, TypeVariable> collectTypeVariables(Class clz) {
    Map<String, TypeVariable> varsMap = new HashMap<String, TypeVariable>();
    LinkedList<Class> classList = new LinkedList<Class>();
    for (Class c = clz; c != null; c = c.getDeclaringClass()) {
      classList.addFirst(c);
    }
    
    for (Class cur : classList) {
      parseTypeParameters(cur, varsMap, true);
    };
    return varsMap;
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
