/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.lang;

// -------------------------------------------------------------------------
// Consensus-safe Thread — Avata/TOS blockchain JVM
//
// Smart-contract code executes in a single deterministic thread.
// - Thread.start() is TRAPPED: spawning host threads breaks consensus.
// - Thread.sleep() is TRAPPED: wall-clock waits break determinism.
// - currentThread() returns the single consensus thread (acceptable).
// - getName(), getId(), getState() are deterministic if fixed.
// Any method that reads/writes host scheduler state is trapped.
// -------------------------------------------------------------------------
public class Thread implements Runnable {
  // set and accessed from within LockSupport
  protected volatile Object parkBlocker;

  private long peer;
  private volatile boolean interrupted;
  private volatile boolean unparked;
  private boolean daemon;
  private byte state;
  private byte priority;
  private final Runnable task;
  private Object sleepLock;
  private ClassLoader classLoader;
  private UncaughtExceptionHandler exceptionHandler;
  private String name;
  private ThreadGroup group;

  private static UncaughtExceptionHandler defaultExceptionHandler;

  public static final int MIN_PRIORITY = 1;
  public static final int NORM_PRIORITY = 5;
  public static final int MAX_PRIORITY = 10;

  private static final String MSG_START =
      "thread creation not available in consensus";
  private static final String MSG_SLEEP =
      "thread sleep not available in consensus";
  private static final String MSG_YIELD =
      "thread yield not available in consensus";
  private static final String MSG_INTERRUPT =
      "thread interruption not available in consensus";
  private static final String MSG_JOIN =
      "thread join not available in consensus";

  public Thread(ThreadGroup group, Runnable task, String name, long stackSize)
  {
    this.group = (group == null ? Thread.currentThread().group : group);
    this.task = task;
    this.name = name;

    Thread current = currentThread();
    classLoader = current.classLoader;
  }

  public Thread(ThreadGroup group, Runnable task, String name) {
    this(group, task, name, 0);
  }

  public Thread(ThreadGroup group, String name) {
    this(null, null, name);
  }

  public Thread(Runnable task, String name) {
    this(null, task, name);
  }

  public Thread(Runnable task) {
    this(null, task, "Thread["+task+"]");
  }

  public Thread(String name) {
    this(null, null, name);
  }

  public Thread() {
    this((Runnable) null);
  }

  // -----------------------------------------------------------------------
  // Thread.start() — TRAPPED
  // -----------------------------------------------------------------------
  public synchronized void start() {
    throw new UnsupportedOperationException(MSG_START);
  }

  private native long doStart();

  private static void run(Thread t) throws Throwable {
    try {
      t.run();
    } catch (Throwable e) {
      UncaughtExceptionHandler eh = t.exceptionHandler;
      UncaughtExceptionHandler deh = defaultExceptionHandler;
      if (eh != null) {
        eh.uncaughtException(t, e);
      } else if (deh != null) {
        deh.uncaughtException(t, e);
      } else {
        throw e;
      }
    } finally {
      synchronized (t) {
        t.state = (byte) State.TERMINATED.ordinal();
        t.notifyAll();
      }
    }
  }

  public void run() {
    if (task != null) {
      task.run();
    }
  }

  public ClassLoader getContextClassLoader() {
    return classLoader;
  }

  public void setContextClassLoader(ClassLoader v) {
    classLoader = v;
  }

  // currentThread() is acceptable: returns the single consensus thread.
  public static native Thread currentThread();

  public void interrupt() {
    throw new ContractViolationError(MSG_INTERRUPT);
  }

  private static native boolean interrupt(long peer);

  public static boolean interrupted() {
    throw new ContractViolationError(MSG_INTERRUPT);
  }

  private static native boolean interrupted(long peer);

  public boolean isInterrupted() {
    throw new ContractViolationError(MSG_INTERRUPT);
  }

  // -----------------------------------------------------------------------
  // Thread.sleep() — TRAPPED
  // -----------------------------------------------------------------------
  public static void sleep(long milliseconds) throws InterruptedException {
    throw new UnsupportedOperationException(MSG_SLEEP);
  }

  public static void sleep(long milliseconds, int nanoseconds)
    throws InterruptedException
  {
    throw new UnsupportedOperationException(MSG_SLEEP);
  }

  public StackTraceElement[] getStackTrace() {
    long p = peer;
    if (p == 0) {
      return new StackTraceElement[0];
    }
    return Throwable.resolveTrace(getStackTrace(p));
  }

  private static native Object getStackTrace(long peer);

  public static int activeCount() {
    return 1;
  }

  public static int enumerate(Thread[] array) {
    if (array != null && array.length > 0) {
      array[0] = currentThread();
      return 1;
    }
    return 0;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public UncaughtExceptionHandler getUncaughtExceptionHandler() {
    UncaughtExceptionHandler eh = exceptionHandler;
    return (eh == null ? group : eh);
  }

  public static UncaughtExceptionHandler getDefaultUncaughtExceptionHandler() {
    return defaultExceptionHandler;
  }

  public void setUncaughtExceptionHandler(UncaughtExceptionHandler h) {
    exceptionHandler = h;
  }

  public static void setDefaultUncaughtExceptionHandler
    (UncaughtExceptionHandler h)
  {
    defaultExceptionHandler = h;
  }

  public State getState() {
    return State.values()[state];
  }

  public boolean isAlive() {
    switch (getState()) {
    case NEW:
    case TERMINATED:
      return false;

    default:
      return true;
    }
  }

  public int getPriority() {
    return priority;
  }

  public void setPriority(int priority) {
    if (priority < MIN_PRIORITY || priority > MAX_PRIORITY) {
      throw new IllegalArgumentException();
    }
    this.priority = (byte) priority;
  }

  public boolean isDaemon() {
    return daemon;
  }

  public synchronized void setDaemon(boolean v) {
    if (getState() != State.NEW) {
      throw new IllegalStateException();
    }

    daemon = v;
  }

  // -----------------------------------------------------------------------
  // Thread.yield() — TRAPPED (reads host scheduler state)
  // -----------------------------------------------------------------------
  public static void yield() {
    throw new UnsupportedOperationException(MSG_YIELD);
  }

  public synchronized void join() throws InterruptedException {
    throw new ContractViolationError(MSG_JOIN);
  }

  public synchronized void join(long milliseconds) throws InterruptedException
  {
    throw new ContractViolationError(MSG_JOIN);
  }

  public void join(long milliseconds, int nanoseconds)
    throws InterruptedException
  {
    throw new ContractViolationError(MSG_JOIN);
  }

  public ThreadGroup getThreadGroup() {
    return group;
  }

  public static native boolean holdsLock(Object o);

  public long getId() {
    return 1;
  }

  public interface UncaughtExceptionHandler {
    public void uncaughtException(Thread t, Throwable e);
  }

  public enum State {
    NEW, RUNNABLE, BLOCKED, WAITING, TIMED_WAITING, TERMINATED
  }

}
