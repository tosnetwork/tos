// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Real production Store calls with unclean child termination, not a chain/finality test.
use anyhow::{bail, ensure, Context, Result};
use rusqlite::{ffi, Connection};
use serde_json::json;
use std::{
    ffi::{c_char, c_int, c_uint, c_void, CStr},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        OnceLock,
    },
    time::{Duration, Instant},
};

// Include the production implementations, without introducing production fault hooks.
#[allow(dead_code, unused_imports)]
#[path = "../src/protocol.rs"]
mod protocol;
#[allow(dead_code, unused_imports)]
#[path = "../src/store.rs"]
mod store;
use store::Store;

const SCOPE: &str = "storage-crash-fixture";
const MESSAGE: &[u8] = b"synthetic immutable message bytes; not a signed wallet envelope";
const RECORD: &[u8] = b"synthetic pre-signing record";
const RECEIPT: &[u8] = b"synthetic refusal or import receipt; not proof";
static CLAIM_STARTED: OnceLock<PathBuf> = OnceLock::new();
static TRACE_FAILED: AtomicBool = AtomicBool::new(false);
static ARMED: AtomicBool = AtomicBool::new(false);
static POINT: OnceLock<String> = OnceLock::new();

fn cut(point: &str) -> ! {
    eprintln!("CUT_REACHED {point}");
    // No Rust/SQLite destructor runs; the parent reopens the actual files.
    std::process::exit(86)
}
unsafe extern "C" fn trace(
    _: c_uint,
    _: *mut c_void,
    statement: *mut c_void,
    _: *mut c_void,
) -> c_int {
    if !ARMED.load(Ordering::Acquire) || statement.is_null() {
        return 0;
    }
    // SQLITE_TRACE_STMT supplies a valid sqlite3_stmt for the duration of this callback.
    let text = unsafe { ffi::sqlite3_sql(statement.cast()) };
    if text.is_null() {
        return 0;
    }
    let sql = unsafe { CStr::from_ptr(text) }.to_string_lossy();
    if sql == "BEGIN IMMEDIATE" {
        if let Some(path) = CLAIM_STARTED.get() {
            if std::fs::write(path, b"entered consume transaction\n").is_err() {
                TRACE_FAILED.store(true, Ordering::Release);
            }
        }
    }
    let Some(point) = POINT.get() else {
        return 0;
    };
    let matched = match point.as_str() {
        "before_commit" => sql == "COMMIT",
        "before_lease_sent" => sql.starts_with("UPDATE leases SET sent=1"),
        "before_permits_retired" => sql.starts_with("UPDATE permits SET used=1"),
        "before_refusal_receipt" => sql.starts_with("INSERT INTO refusals"),
        _ => false,
    };
    if matched {
        cut(point);
    }
    0
}
unsafe extern "C" fn install_trace(
    db: *mut ffi::sqlite3,
    _: *mut *mut c_char,
    _: *const ffi::sqlite3_api_routines,
) -> c_int {
    // The callback is process-local and used only by this standalone test executable.
    unsafe {
        ffi::sqlite3_trace_v2(
            db,
            ffi::SQLITE_TRACE_STMT as c_uint,
            Some(trace),
            std::ptr::null_mut(),
        )
    }
}
fn drive(store: &mut Store, stage: &str) -> Result<()> {
    match stage {
        "reserve" => {
            store.reserve("request", "binding", 7)?;
        }
        "legacy_message" => store.persist_message("request", MESSAGE)?,
        "slot" => store.bind_slot("request", 1)?,
        "quote" => store.claim_quote("request", "quote")?,
        "prepared" => store.persist_prepared("request", MESSAGE, RECORD)?,
        "permit" => store.permit("request", "permit", &protocol::hash(MESSAGE), 100)?,
        "consume" => store.consume("permit", MESSAGE, 101)?,
        "refusal" => store.retire_refused("request", MESSAGE, RECEIPT)?,
        "fee" => store.import_fee("transaction", 3, "note", RECEIPT, &vec![42; 1233])?,
        _ => bail!("unknown fixture stage"),
    }
    Ok(())
}
fn seed(path: &Path, stage: &str) -> Result<()> {
    let mut s = Store::create(path, SCOPE)?;
    if stage != "reserve" {
        s.reserve("request", "binding", 7)?;
    }
    if matches!(stage, "permit" | "consume" | "refusal" | "fee") {
        s.persist_prepared("request", MESSAGE, RECORD)?;
    }
    if matches!(stage, "consume" | "refusal") {
        s.permit("request", "permit", &protocol::hash(MESSAGE), 100)?;
    }
    Ok(())
}
fn child(path: &Path, stage: &str, point: &str) -> Result<()> {
    POINT.set(point.to_string()).map_err(|_| anyhow::anyhow!("duplicate fixture point"))?;
    // Register before opening Store, but arm only after its initialization transactions.
    let rc = unsafe { ffi::sqlite3_auto_extension(Some(install_trace)) };
    ensure!(rc == ffi::SQLITE_OK, "trace extension registration failed");
    let mut store = Store::open(path, SCOPE)?;
    ARMED.store(true, Ordering::Release);
    drive(&mut store, stage)?;
    if point == "after_commit" {
        cut(point);
    }
    bail!("declared SQL cut was never reached")
}
fn command(path: &Path, stage: &str, point: &str) -> Result<Command> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .args(["--child", stage, point])
        .arg(path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    Ok(command)
}
fn finish(mut child: std::process::Child) -> Result<std::process::Output> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if child.try_wait()?.is_some() {
            return Ok(child.wait_with_output()?);
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            bail!("storage child timed out");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn check(path: &Path, stage: &str, committed: bool) -> Result<serde_json::Value> {
    // Reopening through the real boundary triggers hot-journal recovery and scope checks.
    let mut s = Store::open(path, SCOPE)?;
    let db = Connection::open(path)?;
    let count = |table: &str| -> Result<i64> {
        Ok(db.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row.get(0))?)
    };
    let lease = s.lookup("request")?;
    if stage == "reserve" {
        ensure!(lease.is_some() == committed, "reservation crash atomicity");
    }
    if matches!(stage, "legacy_message" | "prepared") {
        let lease = lease.context("fixture lease disappeared")?;
        ensure!(
            lease.message.as_deref() == if committed { Some(MESSAGE) } else { None },
            "message durability"
        );
        let record: Option<Vec<u8>> =
            db.query_row("SELECT record FROM leases WHERE request='request'", [], |row| {
                row.get(0)
            })?;
        ensure!(
            record.as_deref() == if committed && stage == "prepared" { Some(RECORD) } else { None },
            "message/record atomicity"
        );
    }
    if stage == "slot" {
        let slot: Option<i64> =
            db.query_row("SELECT slot FROM leases WHERE request='request'", [], |row| row.get(0))?;
        ensure!(slot == if committed { Some(1) } else { None }, "slot durability");
    }
    if stage == "quote" {
        ensure!(count("quote_claims")? == i64::from(committed), "quote claim durability");
    }
    if stage == "permit" {
        ensure!(count("permits")? == i64::from(committed), "permit durability");
    }
    if stage == "consume" {
        let sent: i64 =
            db.query_row("SELECT sent FROM leases WHERE request='request'", [], |row| row.get(0))?;
        let used: i64 =
            db.query_row("SELECT used FROM permits WHERE token='permit'", [], |row| row.get(0))?;
        ensure!(sent == i64::from(committed) && used == sent, "permit/send-claim atomicity");
        if committed {
            ensure!(s.consume("permit", MESSAGE, 101).is_err(), "consumed permit replay");
        }
    }
    if stage == "refusal" {
        let live: i64 =
            db.query_row("SELECT live FROM leases WHERE request='request'", [], |row| row.get(0))?;
        let used: i64 =
            db.query_row("SELECT used FROM permits WHERE token='permit'", [], |row| row.get(0))?;
        let receipt = s.refusal("request")?;
        ensure!(
            live == i64::from(!committed) && used == i64::from(committed),
            "retirement/permit atomicity"
        );
        ensure!(
            receipt.as_deref() == if committed { Some(RECEIPT) } else { None },
            "retirement/receipt atomicity"
        );
        if committed {
            ensure!(s.consume("permit", MESSAGE, 101).is_err(), "retired permit replay");
            ensure!(
                s.reserve("next", "next-binding", 7)?.fresh,
                "proven retirement must free sequence"
            );
        } else {
            ensure!(
                s.reserve("next", "next-binding", 7).is_err(),
                "uncommitted retirement freed sequence"
            );
        }
    }
    if stage == "fee" {
        ensure!(count("fee_notes")? == i64::from(committed), "fee credit durability");
        if committed {
            s.import_fee("transaction", 3, "note", RECEIPT, &vec![42; 1233])?;
            ensure!(count("fee_notes")? == 1, "duplicate fee credit");
            ensure!(
                s.import_fee("transaction", 3, "other-note", RECEIPT, &vec![42; 1233]).is_err(),
                "changed fee import"
            );
        }
    }
    let integrity: String = db.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    ensure!(integrity == "ok", "SQLite recovery integrity");
    Ok(json!({"stage":stage,"committed":committed,"integrity":integrity}))
}
fn run_case(stage: &str, point: &str) -> Result<serde_json::Value> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("leases.db");
    seed(&path, stage)?;
    let result = finish(command(&path, stage, point)?.spawn()?)?;
    ensure!(
        result.status.code() == Some(86),
        "child did not terminate at intended runtime cut: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    ensure!(
        String::from_utf8_lossy(&result.stderr).contains(&format!("CUT_REACHED {point}")),
        "missing reached-cut receipt"
    );
    let mut row = check(&path, stage, point == "after_commit")?;
    row["point"] = point.into();
    row["child_exit"] = 86.into();
    Ok(row)
}
fn await_files(paths: &[PathBuf], children: &mut [&mut std::process::Child]) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !paths.iter().all(|path| path.is_file()) {
        ensure!(Instant::now() < deadline, "claimant barrier timeout");
        for child in children.iter_mut() {
            ensure!(child.try_wait()?.is_none(), "claimant exited before barrier");
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    Ok(())
}
fn race() -> Result<serde_json::Value> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("leases.db");
    seed(&path, "consume")?;
    let ready = [dir.path().join("ready-a"), dir.path().join("ready-b")];
    let started = [dir.path().join("started-a"), dir.path().join("started-b")];
    let go = dir.path().join("go");
    let spawn = |index: usize| -> Result<std::process::Child> {
        Ok(Command::new(std::env::current_exe()?)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .arg("--claim")
            .arg(&path)
            .arg(&ready[index])
            .arg(&started[index])
            .arg(&go)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?)
    };
    let mut a = spawn(0)?;
    let mut b = match spawn(1) {
        Ok(child) => child,
        Err(error) => {
            a.kill()?;
            a.wait()?;
            return Err(error);
        }
    };
    let barrier = (|| -> Result<()> {
        await_files(&ready, &mut [&mut a, &mut b])?;
        let db = Connection::open(&path)?;
        db.execute_batch("BEGIN IMMEDIATE")?;
        std::fs::write(&go, b"both stores open; enter consumption\n")?;
        // Both processes must enter the real consume BEGIN while a parent lock
        // still excludes either commit. A sequential replay cannot satisfy this.
        await_files(&started, &mut [&mut a, &mut b])?;
        db.execute_batch("ROLLBACK")?;
        Ok(())
    })();
    if let Err(error) = barrier {
        for child in [&mut a, &mut b] {
            let _ = child.kill();
            child.wait()?;
        }
        return Err(error);
    }
    let a = finish(a);
    let b = finish(b);
    let (a, b) = (a?, b?);
    let winners = usize::from(a.status.success()) + usize::from(b.status.success());
    ensure!(winners == 1, "two processes did not have exactly one send claimant");
    for output in [&a, &b] {
        if !output.status.success() {
            ensure!(
                output.status.code() == Some(87)
                    && String::from_utf8_lossy(&output.stderr)
                        .contains("EXPECTED_PERMIT_REJECTION"),
                "losing claimant did not reach the permit guard: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    check(&path, "consume", true)?;
    Ok(
        json!({"stage":"concurrent_consumers","winners":winners,"processes":2,"opened_before_release":2,"entered_consume_while_locked":2,"loser":"EXPECTED_PERMIT_REJECTION"}),
    )
}

fn main() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.get(1).is_some_and(|arg| arg == "--child") {
        ensure!(args.len() == 5, "child argument count");
        return child(Path::new(&args[4]), &args[2], &args[3]);
    }
    if args.get(1).is_some_and(|arg| arg == "--claim") {
        ensure!(args.len() == 6, "claim argument count");
        let rc = unsafe { ffi::sqlite3_auto_extension(Some(install_trace)) };
        ensure!(rc == ffi::SQLITE_OK, "claim trace registration failed");
        let mut s = Store::open(Path::new(&args[2]), SCOPE)?;
        CLAIM_STARTED
            .set(PathBuf::from(&args[4]))
            .map_err(|_| anyhow::anyhow!("claim path already set"))?;
        ARMED.store(true, Ordering::Release);
        std::fs::write(&args[3], b"store opened\n")?;
        let deadline = Instant::now() + Duration::from_secs(15);
        while !Path::new(&args[5]).is_file() {
            ensure!(Instant::now() < deadline, "claim release timeout");
            std::thread::sleep(Duration::from_millis(1));
        }
        let result = s.consume("permit", MESSAGE, 101);
        ensure!(!TRACE_FAILED.load(Ordering::Acquire), "claim trace write failed");
        match result {
            Ok(()) => std::process::exit(0),
            Err(error) if error.to_string() == "permit expired, mismatched or already consumed" => {
                eprintln!("EXPECTED_PERMIT_REJECTION");
                std::process::exit(87);
            }
            Err(error) => return Err(error.context("unexpected storage error in claimant")),
        }
    }
    ensure!(
        args.len() == 1 || (args.len() == 3 && args[1] == "--case"),
        "only optional --case STAGE.POINT supported"
    );
    let selected = args.get(2).map(String::as_str);
    let mut rows = Vec::new();
    for stage in [
        "reserve",
        "legacy_message",
        "slot",
        "quote",
        "prepared",
        "permit",
        "consume",
        "refusal",
        "fee",
    ] {
        for point in ["before_commit", "after_commit"] {
            if selected.is_none_or(|value| value == format!("{stage}.{point}")) {
                rows.push(run_case(stage, point)?);
            }
        }
    }
    for (stage, point) in [
        ("consume", "before_lease_sent"),
        ("refusal", "before_permits_retired"),
        ("refusal", "before_refusal_receipt"),
    ] {
        if selected.is_none_or(|value| value == format!("{stage}.{point}")) {
            rows.push(run_case(stage, point)?);
        }
    }
    if selected.is_none_or(|value| value == "concurrent_consumers") {
        rows.push(race()?);
    }
    ensure!(!rows.is_empty(), "unknown selected case");
    println!(
        "{}",
        serde_json::to_string(
            &json!({"status":"PASS","cases":rows,"scope":"Actual production Store/SQLite and unclean child termination. Synthetic public bytes only; not native signing, network send or chain finality evidence."})
        )?
    );
    Ok(())
}
