/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY; see license.txt for details. */

package java.internal;

final class ExecutionGroup {
  private final ExecutionGroup parent;
  private final String name;
  private Cell<ExecutionGroup> subgroups;

  ExecutionGroup(ExecutionGroup parent, String name) {
    this.parent = parent;
    this.name = name;
  }
}
