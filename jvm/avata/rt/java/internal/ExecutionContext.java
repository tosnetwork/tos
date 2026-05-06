/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY; see license.txt for details. */

package java.internal;

final class ExecutionContext implements Runnable {
  protected volatile Object parkBlocker;

  private long peer;
  private volatile boolean interrupted;
  private volatile boolean unparked;
  private boolean daemon;
  private byte state;
  private byte priority;
  private final Runnable task;
  private Object sleepLock;
  private ClassSpace classSpace;
  private Object exceptionHandler;
  private String name;
  private ExecutionGroup group;
  private Object interruptLock;

  ExecutionContext(ExecutionGroup group, Runnable task, String name, long stackSize) {
    this.group = group;
    this.task = task;
    this.name = name;
  }

  private static void run(ExecutionContext t) throws Throwable {
    t.run();
  }

  public void run() {
    if (task != null) {
      task.run();
    }
  }
}
