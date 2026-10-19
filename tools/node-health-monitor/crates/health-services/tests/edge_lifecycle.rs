#[cfg(unix)]
#[test]
fn edge_exit_does_not_signal_or_restart_configured_source_process() {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        process::{Command, Stdio},
        time::Duration,
    };
    let root = std::env::temp_dir().join(format!(
        "tos-health-edge-lifecycle-{}-{}",
        std::process::id(),
        tos_health_services::hex(&tos_health_services::random_token().unwrap())
    ));
    fs::create_dir(&root).unwrap();
    let token = root.join("edge.token");
    fs::write(&token, "e".repeat(32)).unwrap();
    fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);

    let mut source = Command::new("/bin/sh")
        .args(["-c", "exec sleep 30"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let source_pid = source.id().to_string();
    let listen = address.to_string();
    let mut edge = Command::new(env!("CARGO_BIN_EXE_health-edge"))
        .args(["v1", &source_pid, &listen, token.to_str().unwrap()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert!(edge.try_wait().unwrap().is_none(), "edge failed before lifecycle control");
    edge.kill().unwrap();
    edge.wait().unwrap();
    std::thread::sleep(Duration::from_millis(100));
    assert!(source.try_wait().unwrap().is_none(), "edge exit signalled its configured source");
    source.kill().unwrap();
    source.wait().unwrap();
    fs::remove_dir_all(root).unwrap();
}
