/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.net;

import java.io.IOException;
import java.io.InputStream;

// -------------------------------------------------------------------------
// Consensus-safe URLClassLoader — Avata/TOS blockchain JVM
//
// Dynamic class loading from arbitrary URLs is non-deterministic and a
// security risk in a consensus environment.  All constructors and loading
// operations are TRAPPED.
// -------------------------------------------------------------------------
public class URLClassLoader extends ClassLoader {
  private static final String MSG =
      "networking not available in consensus";

  public URLClassLoader(URL[] urls, ClassLoader parent) {
    super(parent);
    throw new UnsupportedOperationException(MSG);
  }

  public URLClassLoader(URL[] urls) {
    throw new UnsupportedOperationException(MSG);
  }

  protected Class findClass(String name) throws ClassNotFoundException {
    throw new UnsupportedOperationException(MSG);
  }

  public URL getResource(String path) {
    throw new UnsupportedOperationException(MSG);
  }
}
