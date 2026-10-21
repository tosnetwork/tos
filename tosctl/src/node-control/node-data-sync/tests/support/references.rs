use anyhow::Result;
use node_data_sync::{
    model::{FullId, Network},
    references::ReferencePolicy,
};
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::Duration,
};
#[derive(Clone, Copy)]
pub enum Mode {
    Agree,
    Behind,
    DifferentRoot,
    DifferentFile,
    Unavailable,
    Malformed,
    WrongAnchor,
}
pub struct References {
    pub policy: ReferencePolicy,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}
fn block(id: &FullId) -> serde_json::Value {
    use base64::Engine;
    serde_json::json!({"@type":"tos.blockIdExt","workchain":id.workchain,"shard":id.shard.to_string(),"seqno":id.seqno,"root_hash":base64::engine::general_purpose::STANDARD.encode(hex::decode(&id.root_hash).unwrap()),"file_hash":base64::engine::general_purpose::STANDARD.encode(hex::decode(&id.file_hash).unwrap())})
}
impl References {
    pub fn new(network: &Network, frontier: &FullId, mode: Mode) -> Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let mut threads = Vec::new();
        let mut endpoints = Vec::new();
        for mode in [Mode::Agree, mode] {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            listener.set_nonblocking(true)?;
            endpoints.push(format!("http://{}", listener.local_addr()?));
            let stop = stop.clone();
            let frontier = frontier.clone();
            let zero = network.zero.clone();
            threads.push(std::thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    let (mut socket, _) = match listener.accept() { Ok(value)=>value, Err(e) if e.kind()==std::io::ErrorKind::WouldBlock => { std::thread::sleep(Duration::from_millis(2)); continue; }, Err(e)=>panic!("reference accept: {e}") };
                    if matches!(mode, Mode::Unavailable) { continue; }
                    socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                    let mut header=Vec::new();
                    while !header.ends_with(b"\r\n\r\n") { let mut byte=[0]; if socket.read(&mut byte).unwrap_or(0)!=1 {break;} header.push(byte[0]); assert!(header.len()<8192); }
                    if !header.ends_with(b"\r\n\r\n") {continue;}
                    let header=String::from_utf8(header).unwrap();
                    assert!(matches!(header.lines().next(), Some("POST /jsonRPC HTTP/1.1" | "POST /jsonRPC? HTTP/1.1")), "incorrect RPC route: {header}");
                    let length:usize=header.lines().find_map(|line|line.to_ascii_lowercase().strip_prefix("content-length:").map(|v|v.trim().parse().unwrap())).unwrap();
                    assert!(length<8192); let mut body=vec![0;length];socket.read_exact(&mut body).unwrap();
                    let request:serde_json::Value=serde_json::from_slice(&body).unwrap();
                    let mut head=frontier.clone();head.seqno+=1;
                    if matches!(mode,Mode::Behind) {head.seqno=frontier.seqno.saturating_sub(1);}
                    let result=match request["method"].as_str().unwrap() {
                        "getMasterchainInfo" => { let mut anchor=zero.clone(); if matches!(mode,Mode::WrongAnchor) {anchor.root_hash="ef".repeat(32);} serde_json::json!({"last":block(&head),"init":block(&anchor)}) },
                        "lookupBlock" => {assert_eq!(request["params"]["seqno"], frontier.seqno); let mut at=frontier.clone(); if matches!(mode,Mode::DifferentRoot){at.root_hash="ef".repeat(32);} if matches!(mode,Mode::DifferentFile){at.file_hash="ef".repeat(32);} block(&at)},
                        other=>panic!("unexpected reference method {other}")
                    };
                    let payload=if matches!(mode,Mode::Malformed){b"{".to_vec()}else{serde_json::to_vec(&serde_json::json!({"jsonrpc":"2.0","id":request["id"],"result":result})).unwrap()};
                    let _=write!(socket,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",payload.len());let _=socket.write_all(&payload);
                }
            }));
        }
        Ok(Self { policy: ReferencePolicy::from_endpoints(&endpoints)?, stop, threads })
    }
}
impl Drop for References {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        for thread in self.threads.drain(..) {
            assert!(thread.join().is_ok(), "reference fixture failed");
        }
    }
}
pub fn network(frontier: &FullId) -> Network {
    let mut zero = frontier.clone();
    zero.seqno = 0;
    Network { global_id: 3, zero: zero.clone(), init: zero }
}
pub fn receipt(
    network: &Network,
    frontier: &FullId,
    binding: &str,
) -> node_data_sync::references::ReferenceReceipt {
    let refs = References::new(network, frontier, Mode::Agree).unwrap();
    refs.policy.corroborate(network, frontier, binding).unwrap().receipt().unwrap()
}
pub fn historical_receipt(
    network: &Network,
    frontier: &FullId,
    binding: &str,
    utc: u64,
) -> node_data_sync::references::ReferenceReceipt {
    use node_data_sync::references::{NamedReference, ReferenceAnswer, ReferenceReceipt};
    ReferenceReceipt {
        network: network.clone(),
        frontier: frontier.clone(),
        binding_sha256: binding.to_owned(),
        started_utc: utc,
        finished_utc: utc,
        answers: (1..=2)
            .map(|n| ReferenceAnswer {
                source: NamedReference {
                    name: format!("fixture-{n}"),
                    endpoint: format!("http://127.0.0.1:{n}"),
                },
                head: frontier.clone(),
                at_frontier: frontier.clone(),
                observed_utc: utc,
            })
            .collect(),
    }
}
pub fn authorize(
    journal: &mut node_data_sync::journal::Journal,
    operation: &node_data_sync::safe_io::Root,
) -> Result<()> {
    let frontier = journal.target_anchor.clone();
    let network = network(&frontier);
    let refs = References::new(&network, &frontier, Mode::Agree)?;
    let approval = refs.policy.corroborate(&network, &frontier, &journal.reference_binding())?;
    journal.authorize(operation, &approval)
}
