use serde_json::json;
use std::{path::PathBuf,os::unix::fs::PermissionsExt,process::Command,sync::Arc,time::Duration};
use tos_health_services::{diagnostic_relay::{self,Config,Stats},diagnostic_ipc::Mapping,diagnostic_transport::Destination,
    manager::{Manager,ManagerConfig},ingress::{IngressConfig,Peer,Role}};
use sha2::{Digest,Sha256};
struct Fixture(PathBuf);
impl Drop for Fixture {fn drop(&mut self){let _=std::fs::remove_dir_all(&self.0);}}
fn fixture()->Fixture {
    let path=std::env::temp_dir().join(format!("nhm-d-{}",&tos_health_services::hex(&tos_health_services::random_token().unwrap())[..16]));
    std::fs::create_dir(&path).unwrap();std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o700)).unwrap();
    let commands=vec![vec!["req","-x509","-newkey","ec","-pkeyopt","ec_paramgen_curve:prime256v1","-nodes","-keyout","ca.key","-out","ca.pem","-subj","/CN=nhm-ca","-days","1","-addext","basicConstraints=critical,CA:TRUE"]];
    for args in commands {assert!(Command::new("openssl").args(args).current_dir(&path).output().unwrap().status.success());}
    for name in ["server","client"] {
        assert!(Command::new("openssl").args(["req","-new","-newkey","ec","-pkeyopt","ec_paramgen_curve:prime256v1","-nodes","-keyout",&format!("{name}.key"),"-out",&format!("{name}.csr"),"-subj",&format!("/CN={name}")]).current_dir(&path).output().unwrap().status.success());
        let ext=if name=="server" {"basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n"} else {"basicConstraints=CA:FALSE\nextendedKeyUsage=clientAuth\n"};
        std::fs::write(path.join(format!("{name}.ext")),ext).unwrap();
        assert!(Command::new("openssl").args(["x509","-req","-in",&format!("{name}.csr"),"-CA","ca.pem","-CAkey","ca.key","-set_serial",if name=="server" {"1"} else {"2"},"-days","1","-extfile",&format!("{name}.ext"),"-out",&format!("{name}.pem")]).current_dir(&path).output().unwrap().status.success());
    }
    let mut identity=std::fs::read(path.join("client.pem")).unwrap();identity.extend(std::fs::read(path.join("client.key")).unwrap());std::fs::write(path.join("identity.pem"),identity).unwrap();
    std::fs::set_permissions(path.join("identity.pem"),std::fs::Permissions::from_mode(0o600)).unwrap();
    for (name,value) in [("ingest",'a'),("read",'b'),("diagnostic",'c')] {
        let file=path.join(name);std::fs::write(&file,value.to_string().repeat(32)).unwrap();std::fs::set_permissions(file,std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    Fixture(path)
}
fn manager_config(f:&Fixture)->ManagerConfig {
    serde_json::from_value(json!({"inventory":{"schema_version":1,"revision":"c06-local","network_id":"a".repeat(64),"targets":[{"node":"v1","scope":"node","sources":[{"id":"edge_probe","ttl_ms":"45000","facts":["reachable"]}],"rules":[{"id":"target_unreachable","source":"edge_probe","threshold":"0","pending_ms":"0","recovery_ms":"60000","minimum_bad_samples":1,"severity":"critical"}]}]},
        "control_db":f.0.join("control.db"),"evidence_db":f.0.join("evidence.db"),"control_quota_bytes":"1048576","evidence_quota_bytes":"16777216","listen":"127.0.0.1:0",
        "ingest_token_file":f.0.join("ingest"),"read_token_file":f.0.join("read"),"receiver":null,"diagnostic":{"token_file":f.0.join("diagnostic"),"nodes":["v1"]}})).unwrap()
}
#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn actual_native_ipc_relay_mtls_manager_transaction_chain() {
    let f=fixture();let config=manager_config(&f);let manager=Manager::start(&config).unwrap();
    let up=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let upstream=up.local_addr().unwrap();
    let app=tos_health_services::manager::router(manager.clone());let serving=tokio::spawn(async move {axum::serve(up,app).await.unwrap()});
    let tls=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let address=tls.local_addr().unwrap();
    let der=Command::new("openssl").args(["x509","-in","client.pem","-outform","DER"]).current_dir(&f.0).output().unwrap();assert!(der.status.success());
    let ingress=IngressConfig {listen:address,server_name:"localhost".into(),upstream,cert_file:f.0.join("server.pem"),key_file:f.0.join("server.key"),ca_file:f.0.join("ca.pem"),witness_endpoints:vec![],
        peers:vec![Peer {alias:"diagnostic_edge".into(),certificate_sha256:format!("{:x}",Sha256::digest(der.stdout)),role:Role::DiagnosticSender}]};
    let ingress_task=tokio::spawn(tos_health_services::ingress::serve(ingress,tls));
    let root=PathBuf::from(env!("CARGO_MANIFEST_DIR")).ancestors().nth(4).unwrap().to_path_buf();
    let bridge=f.0.join("native-bridge");let compile=Command::new("g++").args(["-std=c++20","-O2","-pthread","-I"]).arg(&root).arg(root.join("tools/node-health-monitor/tests/native/diagnostic-bridge.cpp")).arg("-o").arg(&bridge).output().unwrap();
    assert!(compile.status.success(),"{}",String::from_utf8_lossy(&compile.stderr));
    // Spawn the native process before creating its fixed credential allowlist.
    // The private path may be absent; its pump connects only after approved bind.
    let socket=f.0.join("diagnostic.sock");let epoch="23".repeat(16);
    let mut native=Command::new(&bridge).arg(&socket).arg(std::process::id().to_string()).arg(&epoch).stdin(std::process::Stdio::piped()).spawn().unwrap();
    let relay_config=Config {mapping:Mapping {socket_path:socket,node_id:"v1".into(),native_pid:native.id() as i32,native_uid:unsafe{libc::getuid()},native_gid:unsafe{libc::getgid()},process_epoch:epoch},
        destination:Destination {origin:format!("https://localhost:{}/",address.port()),ca_file:f.0.join("ca.pem"),identity_file:f.0.join("identity.pem"),token_file:f.0.join("diagnostic")}};
    let stats=Arc::new(Stats::default());let (stop,stopping)=tokio::sync::watch::channel(false);let relay=tokio::spawn(diagnostic_relay::run(relay_config,stats.clone(),stopping));
    tokio::time::timeout(Duration::from_secs(2),async {while !stats.running.load(std::sync::atomic::Ordering::Relaxed) {tokio::time::sleep(Duration::from_millis(5)).await;}}).await.unwrap();
    {use std::io::Write;native.stdin.take().unwrap().write_all(b"go\n").unwrap();}
    let native_result=tokio::task::spawn_blocking(move ||native.wait().unwrap()).await.unwrap();assert!(native_result.success());
    tokio::time::timeout(Duration::from_secs(8),async {
        while stats.accepted.load(std::sync::atomic::Ordering::Relaxed)!=10 {tokio::time::sleep(Duration::from_millis(25)).await;}
    }).await.expect("real native records must be ACKed through TLS into M");
    let db=rusqlite::Connection::open(&config.evidence_db).unwrap();
    assert_eq!(db.query_row("SELECT count(*) FROM observations WHERE source='consensus_diagnostic'",[],|r|r.get::<_,u64>(0)).unwrap(),10);
    assert_eq!(stats.rejected.load(std::sync::atomic::Ordering::Relaxed),0);
    stop.send(true).unwrap();assert!(tokio::time::timeout(Duration::from_secs(1),relay).await.unwrap().unwrap().is_ok());
    ingress_task.abort();serving.abort();drop(manager);drop(db);
}
