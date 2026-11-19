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

    Copyright 2025-2026 TOS Blockchain Teams
*/
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import org.tos.toslib.Client;
import org.tos.toslib.TosApi;

/**
 * Drives the toslib JNI binding (example/android) in a desktop JVM, against the
 * host build of the same native-lib.cpp and Client.java an Android app loads.
 * Exits non-zero on the first check that does not hold.
 */
public final class ToslibJniSmokeTest {
    private static int checks = 0;

    private static void check(boolean condition, String what) {
        if (!condition) {
            System.err.println("FAIL: " + what);
            System.exit(1);
        }
        checks++;
        System.out.println("ok: " + what);
    }

    public static void main(String[] args) throws Exception {
        // Synchronous requests: Java object to native and back.
        TosApi.Object set = Client.execute(new TosApi.SetLogVerbosityLevel(2));
        check(set instanceof TosApi.Ok, "setLogVerbosityLevel executes synchronously: " + set);
        TosApi.Object level = Client.execute(new TosApi.GetLogVerbosityLevel());
        check(level instanceof TosApi.LogVerbosityLevel && ((TosApi.LogVerbosityLevel) level).verbosityLevel == 2,
                "getLogVerbosityLevel returns the level just set: " + level);
        check(level.toString().contains("verbosityLevel"), "Object.toString is the registered native method");
        TosApi.Object refused = Client.execute(new TosApi.Close());
        check(refused instanceof TosApi.Error, "a request toslib does not run synchronously is answered with an error: " + refused);

        // Asynchronous requests through the client's receiving thread.
        BlockingQueue<TosApi.Object> answers = new ArrayBlockingQueue<>(4);
        Client client = Client.create(null, null, null);
        client.send(new TosApi.GetLogVerbosityLevel(), answers::add);
        TosApi.Object answer = answers.poll(30, TimeUnit.SECONDS);
        check(answer instanceof TosApi.LogVerbosityLevel, "send is answered on the receiving thread: " + answer);

        client.close();
        client.send(new TosApi.GetLogVerbosityLevel(), answers::add);
        TosApi.Object afterClose = answers.poll(1, TimeUnit.SECONDS);
        check(afterClose instanceof TosApi.Error && ((TosApi.Error) afterClose).code == 500,
                "a request after close is answered with an error: " + afterClose);
        client.close();
        check(true, "a second close returns");

        System.out.println("toslib JNI smoke test: " + checks + " checks passed");
    }
}
