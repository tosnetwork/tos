/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TOS Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TOS Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2017-2020 Telegram Systems LLP
    Copyright 2025-2026 TOS Blockchain Teams
*/
package org.tos.toslib;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Main class for interaction with toslib. Requests are sent with {@link #send} and
 * answered on a thread of the client's own; {@link #close} stops it.
 */
public final class Client implements Runnable, AutoCloseable {
    static {
        System.loadLibrary("native-lib");
    }

    /** Interface for handlers of results of queries to toslib and of updates from it. */
    public interface ResultHandler {
        /**
         * Callback called on result of query to toslib or on a new update.
         *
         * @param object Result of the query, or an update.
         */
        void onResult(TosApi.Object object);
    }

    /** Interface for handlers of exceptions thrown from a ResultHandler. */
    public interface ExceptionHandler {
        /**
         * Callback called on exceptions thrown from a ResultHandler.
         *
         * @param e Exception thrown from the ResultHandler.
         */
        void onException(Throwable e);
    }

    /**
     * Sends a request to toslib.
     *
     * @param query            Object representing a query to toslib.
     * @param resultHandler    Result handler, called with the result of the query or with
     *                         TosApi.Error. If it is null, nothing is called.
     * @param exceptionHandler Handler for exceptions thrown from resultHandler. If it is null,
     *                         the default exception handler is called.
     * @throws NullPointerException if query is null.
     */
    public void send(TosApi.Function query, ResultHandler resultHandler, ExceptionHandler exceptionHandler) {
        if (query == null) {
            throw new NullPointerException("query is null");
        }

        readLock.lock();
        try {
            if (!isClientDestroyed) {
                long queryId = currentQueryId.incrementAndGet();
                handlers.put(queryId, new Handler(resultHandler, exceptionHandler));
                nativeClientSend(nativeClientId, queryId, query);
                return;
            }
        } finally {
            readLock.unlock();
        }
        // The handler runs without the lock: it may call close(), which takes the
        // write lock and could never get it from a thread holding the read lock.
        if (resultHandler != null) {
            handleResult(new TosApi.Error(500, "Client is closed"), resultHandler, exceptionHandler);
        }
    }

    /**
     * Sends a request to toslib with the default exception handler.
     *
     * @param query         Object representing a query to toslib.
     * @param resultHandler Result handler, called with the result of the query or with
     *                      TosApi.Error. If it is null, nothing is called.
     * @throws NullPointerException if query is null.
     */
    public void send(TosApi.Function query, ResultHandler resultHandler) {
        send(query, resultHandler, null);
    }

    /**
     * Synchronously executes a toslib request. Only the requests toslib marks as
     * synchronous can be executed this way; any other is answered with TosApi.Error.
     *
     * @param query Object representing a query to toslib.
     * @return the result of the request.
     * @throws NullPointerException if query is null.
     */
    public static TosApi.Object execute(TosApi.Function query) {
        if (query == null) {
            throw new NullPointerException("query is null");
        }
        return nativeClientExecute(query);
    }

    /**
     * Replaces the handler for updates from toslib.
     *
     * @param updatesHandler   Handler called for every update from toslib.
     * @param exceptionHandler Handler for exceptions thrown from updatesHandler. If it is null,
     *                         the default exception handler is called.
     */
    public void setUpdatesHandler(ResultHandler updatesHandler, ExceptionHandler exceptionHandler) {
        handlers.put(0L, new Handler(updatesHandler, exceptionHandler));
    }

    /**
     * Replaces the handler for updates from toslib, with the default exception handler.
     *
     * @param updatesHandler Handler called for every update from toslib.
     */
    public void setUpdatesHandler(ResultHandler updatesHandler) {
        setUpdatesHandler(updatesHandler, null);
    }

    /**
     * Replaces the exception handler called for exceptions thrown from any ResultHandler
     * that has none of its own.
     *
     * @param defaultExceptionHandler Default exception handler. If null, exceptions are ignored.
     */
    public void setDefaultExceptionHandler(Client.ExceptionHandler defaultExceptionHandler) {
        this.defaultExceptionHandler = defaultExceptionHandler;
    }

    /** The client's receiving thread; do not call it directly. */
    @Override
    public void run() {
        while (!stopFlag) {
            receiveQueries(RECEIVE_TIMEOUT_SECONDS);
        }
    }

    /**
     * Creates a client and starts its receiving thread.
     *
     * @param updatesHandler          Handler for updates.
     * @param updatesExceptionHandler Handler for exceptions thrown from updatesHandler.
     * @param defaultExceptionHandler Handler for exceptions thrown from any other ResultHandler.
     * @return the created client.
     */
    public static Client create(
            ResultHandler updatesHandler, ExceptionHandler updatesExceptionHandler, ExceptionHandler defaultExceptionHandler) {
        Client client = new Client(updatesHandler, updatesExceptionHandler, defaultExceptionHandler);
        client.receiver = new Thread(client, "toslib thread");
        client.receiver.start();
        return client;
    }

    /**
     * Closes the client. toslib answers the close request after every request sent before
     * it; that answer stops the receiving thread, which this waits for. A request still
     * waiting for an answer then is answered here with TosApi.Error. The native client is
     * destroyed last. Calling it again does nothing.
     *
     * @throws IllegalStateException if called from a result handler, which runs on the
     *                               receiving thread this would wait for.
     */
    @Override
    public void close() {
        if (Thread.currentThread() == receiver) {
            throw new IllegalStateException("close() called from a toslib result handler");
        }
        writeLock.lock();
        try {
            if (isClientDestroyed) {
                return;
            }
            long closeId = currentQueryId.incrementAndGet();
            handlers.put(closeId, new Handler(object -> stopFlag = true, null));
            nativeClientSend(nativeClientId, closeId, new TosApi.Close());
            isClientDestroyed = true;
        } finally {
            writeLock.unlock();
        }

        boolean interrupted = false;
        while (receiver != null && receiver.isAlive()) {
            try {
                receiver.join();
            } catch (InterruptedException e) {
                interrupted = true;
            }
        }
        for (Map.Entry<Long, Handler> entry : handlers.entrySet()) {
            if (entry.getKey() != 0L && handlers.remove(entry.getKey()) != null) {
                handleResult(new TosApi.Error(500, "Client is closed"),
                        entry.getValue().resultHandler, entry.getValue().exceptionHandler);
            }
        }
        destroyNativeClient(nativeClientId);
        if (interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    private final ReadWriteLock readWriteLock = new ReentrantReadWriteLock();
    private final Lock readLock = readWriteLock.readLock();
    private final Lock writeLock = readWriteLock.writeLock();

    private volatile boolean stopFlag = false;
    private volatile boolean isClientDestroyed = false;
    private volatile Thread receiver = null;
    private final long nativeClientId;

    private final ConcurrentHashMap<Long, Handler> handlers = new ConcurrentHashMap<Long, Handler>();
    private final AtomicLong currentQueryId = new AtomicLong();

    private volatile ExceptionHandler defaultExceptionHandler = null;

    private static final double RECEIVE_TIMEOUT_SECONDS = 300.0;
    private static final int MAX_EVENTS = 1000;
    private final long[] eventIds = new long[MAX_EVENTS];
    private final TosApi.Object[] events = new TosApi.Object[MAX_EVENTS];

    private static class Handler {
        final ResultHandler resultHandler;
        final ExceptionHandler exceptionHandler;

        Handler(ResultHandler resultHandler, ExceptionHandler exceptionHandler) {
            this.resultHandler = resultHandler;
            this.exceptionHandler = exceptionHandler;
        }
    }

    private Client(ResultHandler updatesHandler, ExceptionHandler updateExceptionHandler, ExceptionHandler defaultExceptionHandler) {
        nativeClientId = createNativeClient();
        handlers.put(0L, new Handler(updatesHandler, updateExceptionHandler));
        this.defaultExceptionHandler = defaultExceptionHandler;
    }

    private void processResult(long id, TosApi.Object object) {
        Handler handler;
        if (id == 0) {
            // The update handler stays for the life of the client.
            handler = handlers.get(id);
        } else {
            handler = handlers.remove(id);
        }
        if (handler == null) {
            return;
        }
        handleResult(object, handler.resultHandler, handler.exceptionHandler);
    }

    private void handleResult(TosApi.Object object, ResultHandler resultHandler, ExceptionHandler exceptionHandler) {
        if (resultHandler == null) {
            return;
        }
        try {
            resultHandler.onResult(object);
        } catch (Throwable cause) {
            if (exceptionHandler == null) {
                exceptionHandler = defaultExceptionHandler;
            }
            if (exceptionHandler != null) {
                try {
                    exceptionHandler.onException(cause);
                } catch (Throwable ignored) {
                    // An exception handler that throws has nobody left to report to.
                }
            }
        }
    }

    private void receiveQueries(double timeout) {
        int resultN = nativeClientReceive(nativeClientId, eventIds, events, timeout);
        for (int i = 0; i < resultN; i++) {
            processResult(eventIds[i], events[i]);
            events[i] = null;
        }
    }

    private static native long createNativeClient();

    private static native void nativeClientSend(long nativeClientId, long eventId, TosApi.Function function);

    private static native int nativeClientReceive(long nativeClientId, long[] eventIds, TosApi.Object[] events, double timeout);

    private static native TosApi.Object nativeClientExecute(TosApi.Function function);

    private static native void destroyNativeClient(long nativeClientId);
}
