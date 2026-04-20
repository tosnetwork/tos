/*
    uno/crypto/internal/avatar_log_stubs.c
    ======================================

    Minimal stubs for the handful of avatar-infrastructure log symbols that
    `~/avatar/src/crypto/blake3/at_blake3.c` links against. Compiling the
    full `~/avatar/src/infra/log/at_log.c` would drag in avatar's
    shared-memory log-ring machinery (lock_memfd, app_id, etc.), which we
    don't need for a pure BLAKE3 hasher.

    These stubs are no-ops — BLAKE3 only uses the log APIs for
    human-debuggable tracing. The crypto path itself never branches on the
    log state. No on-chain / consensus data touches these symbols.

    Keep this file PRIVATE to uno_workchain (never export via a public
    header); if a future avatar primitive needs real logging, replace the
    no-op stubs with calls into TOS's own LOG() infrastructure or compile
    avatar's at_log.c directly.
*/

typedef unsigned long ulong;

/* at_log_wallclock: returns current wall-clock ns. BLAKE3 only uses it to
   timestamp log lines; returning 0 is fine for our purposes. */
ulong at_log_wallclock(void) {
    return 0UL;
}

/* at_log_private_0 / _1 / ...: avatar's log-format rendering helpers.
   Variadic signature varies; we declare them as "absorb everything" stubs.
   Unused in the crypto path. */
int at_log_private_0(const char* fmt, ...) {
    (void)fmt;
    return 0;
}

int at_log_private_1(const char* fmt, ...) {
    (void)fmt;
    return 0;
}

int at_log_private_2(const char* fmt, ...) {
    (void)fmt;
    return 0;
}

int at_log_private_3(const char* fmt, ...) {
    (void)fmt;
    return 0;
}

int at_log_private_4(const char* fmt, ...) {
    (void)fmt;
    return 0;
}
