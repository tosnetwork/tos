//! Actual command delegation with a real file Vault and a read-only RPC fixture.
//! The nested spend-limit refusal is before custody, signing and submission.
use super::*;
use clap::Parser;
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Parser)]
struct TaskParser {
    #[command(subcommand)]
    action: AgentTaskAction,
}

#[test]
fn via_agent_task_releases_outer_file_vault_before_delegation() {
    const EXACT: &str = "commands::nodectl::agent_cmd::task_vault_tests::via_agent_task_releases_outer_file_vault_before_delegation";
    let runtime = tokio::runtime::Runtime::new().unwrap();
    if std::env::var_os("TOS_TEST_TASK_VAULT_DELEGATION_CHILD").is_none() {
        let vault = runtime.block_on(super::super::utils::test_vault::with_ed25519_keys(&[]));
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", EXACT, "--nocapture"])
            .env("TOS_TEST_TASK_VAULT_DELEGATION_CHILD", "1")
            .env("VAULT_URL", &vault.url)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "command delegation regression:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("TASK_VAULT_DELEGATION_OK"));
        return;
    }
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("agent_vault_rpc_fixture.json")).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}/jsonRPC", listener.local_addr().unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let unexpected = Arc::new(AtomicBool::new(false));
    let task_status = Arc::new(AtomicU8::new(0));
    let nested_reads = Arc::new(AtomicUsize::new(0));
    let protected_reads = Arc::new(AtomicUsize::new(0));
    let thread = {
        let (stop, unexpected, task_status, nested_reads, protected_reads, fixture) = (
            stop.clone(),
            unexpected.clone(),
            task_status.clone(),
            nested_reads.clone(),
            protected_reads.clone(),
            fixture.clone(),
        );
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(30);
            let runtime = tokio::runtime::Runtime::new().unwrap();
            while !stop.load(Ordering::SeqCst) && Instant::now() < deadline {
                let (mut stream, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("accept: {error}"),
                };
                stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                let mut data = Vec::new();
                let mut part = [0; 4096];
                let (header_end, length) = loop {
                    let n = stream.read(&mut part).unwrap();
                    assert!(n > 0);
                    data.extend_from_slice(&part[..n]);
                    assert!(data.len() < 65536, "bounded test request");
                    if let Some(end) = data.windows(4).position(|p| p == b"\r\n\r\n") {
                        let header = String::from_utf8_lossy(&data[..end]).to_ascii_lowercase();
                        let size = header
                            .lines()
                            .find_map(|line| {
                                line.strip_prefix("content-length:")
                                    .map(|s| s.trim().parse::<usize>().unwrap())
                            })
                            .unwrap();
                        break (end + 4, size);
                    }
                };
                while data.len() < header_end + length {
                    let n = stream.read(&mut part).unwrap();
                    assert!(n > 0);
                    data.extend_from_slice(&part[..n]);
                    assert!(data.len() < 65536);
                }
                let request: serde_json::Value =
                    serde_json::from_slice(&data[header_end..header_end + length]).unwrap();
                let result = match request["method"].as_str().unwrap() {
                    "runGetMethodStd" => match request["params"]["method"].as_str().unwrap() {
                        "get_task_data" => {
                            let mut task = fixture["task"].clone();
                            task["stack"][11]["number"]["number"] =
                                serde_json::json!(task_status.load(Ordering::SeqCst).to_string());
                            task
                        }
                        "get_agent_account_data" => {
                            nested_reads.fetch_add(1, Ordering::SeqCst);
                            let url = std::env::var("VAULT_URL").unwrap();
                            let error = runtime
                                .block_on(
                                    secrets_vault::vault_builder::SecretVaultBuilder::from_url(
                                        &url,
                                    ),
                                )
                                .err()
                                .expect("nested command must still hold exclusive Vault");
                            assert!(
                                error
                                    .to_string()
                                    .contains("Vault is already open or cannot be locked")
                            );
                            protected_reads.fetch_add(1, Ordering::SeqCst);
                            fixture["agent"].clone()
                        }
                        _ => {
                            unexpected.store(true, Ordering::SeqCst);
                            serde_json::Value::Null
                        }
                    },
                    "getAddressInformation" => fixture["task_account_info"].clone(),
                    "getMasterchainInfo" => fixture["master"].clone(),
                    "getBlockHeader" => fixture["header"].clone(),
                    "getConfigParam" if request["params"]["config_id"] == 19 => {
                        fixture["config19"].clone()
                    }
                    _ => {
                        unexpected.store(true, Ordering::SeqCst);
                        serde_json::Value::Null
                    }
                };
                let response = serde_json::to_vec(
                    &serde_json::json!({"jsonrpc":"2.0","id":request["id"],"result":result}),
                )
                .unwrap();
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n", response.len()).unwrap();
                stream.write_all(&response).unwrap();
            }
        })
    };
    let directory = tempfile::Builder::new()
        .permissions({
            use std::os::unix::fs::PermissionsExt;
            fs::Permissions::from_mode(0o700)
        })
        .tempdir()
        .unwrap();
    let config = serde_json::json!({"nodes":{},"http":{},"chain_rpc":{"urls":[endpoint]},
        "agent_tasks":{"task":fixture["task_record"]},
        "agent_wallets":{"worker":{"wallet":{"key":{"name":"unused"},"version":"V3R2","subwallet_id":42},
            "controller_key":{"name":"unused"},"policy":{"max_per_tx":1,"daily_limit":2},
            "agent_account_address":fixture["account"]}}});
    let path = directory.path().join("config.json");
    write_private_snapshot_file(&path, &serde_json::to_vec(&config).unwrap()).unwrap();
    runtime.block_on(async {
        for operation in ["accept", "reject", "result"] {
            task_status.store(if operation == "result" { 1 } else { 0 }, Ordering::SeqCst);
            let action = TaskParser::try_parse_from([
                "task",
                "send",
                "--operation",
                operation,
                "--name",
                "task",
                "--via-agent-account",
                "worker",
                "--amount-nanotos",
                "100000000",
                "--controller-action-id",
                &"ab".repeat(32),
                "--result-hash",
                &"cd".repeat(32),
                "--evidence-hash",
                &"ef".repeat(32),
                "--yes",
                "--quorum-config",
                "/private/observer1.json",
                "/private/observer2.json",
            ])
            .unwrap()
            .action;
            let AgentTaskAction::Send(command) = action else { panic!("send command") };
            let error = command.run(path.to_str().unwrap()).await.unwrap_err();
            assert!(
                error.to_string().contains("exceeds Agent Account max_per_tx"),
                "nested limit guard must be reached, got {error}"
            );
        }
        let url = std::env::var("VAULT_URL").unwrap();
        let held = secrets_vault::vault_builder::SecretVaultBuilder::from_url(&url).await.unwrap();
        assert!(
            secrets_vault::vault_builder::SecretVaultBuilder::from_url(&url).await.is_err(),
            "exclusion must remain enforced"
        );
        drop(held);
    });
    stop.store(true, Ordering::SeqCst);
    thread.join().unwrap();
    assert_eq!(nested_reads.load(Ordering::SeqCst), 3);
    assert_eq!(protected_reads.load(Ordering::SeqCst), 3);
    assert!(!unexpected.load(Ordering::SeqCst), "no signing/submission or unexpected RPC");
    let journal = directory.path().join(".tosctl-agent-controller-journal");
    assert!(
        !fs::read_dir(journal).unwrap().any(|entry| entry
            .unwrap()
            .path()
            .extension()
            .is_some_and(|e| e == "json")),
        "no custody action created before limit refusal"
    );
    println!("TASK_VAULT_DELEGATION_OK");
}
