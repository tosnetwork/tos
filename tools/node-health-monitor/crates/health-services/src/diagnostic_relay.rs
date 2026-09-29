//! Bounded, lossy diagnostics. Neither retries nor receipt ACKs assert consensus.
use crate::{diagnostic_ingest::Ack,diagnostic_ipc::{Mapping,Received,Receiver},diagnostic_transport::{Destination,Transport}};
use serde::{Deserialize,Serialize};
use std::{collections::VecDeque,path::Path,sync::{Arc,Mutex,atomic::{AtomicBool,AtomicU64,Ordering}},time::{Duration,Instant}};
use tos_health_core::{contracts::{DiagnosticBatch,DiagnosticItem,DiagnosticQuality},wire::{DiagnosticRecord,U64}};
const RECORDS:usize=4096;
const QUEUE_BYTES:usize=4*1024*1024;
const AGE:Duration=Duration::from_secs(30);
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {pub mapping:Mapping,pub destination:Destination}
impl Config {
    pub fn read(path:&Path)->Result<Self,String> {
        serde_json::from_slice(&crate::diagnostic_ipc::read_regular(path,16384,true)?).map_err(|e|e.to_string())
    }
}
#[derive(Default)]
pub struct Stats {
    pub received:AtomicU64,pub rejected:AtomicU64,pub capacity_dropped:AtomicU64,pub expired:AtomicU64,
    pub ack_rejected:AtomicU64,pub accepted:AtomicU64,pub queued_records:AtomicU64,pub queued_bytes:AtomicU64,
    pub gaps:AtomicBool,pub running:AtomicBool,pub counter_complete:AtomicBool,
}
impl Stats {
    pub fn snapshot(&self)->serde_json::Value {
        serde_json::json!({"schema_version":1,"running":self.running.load(Ordering::Relaxed),"counter_complete":self.counter_complete.load(Ordering::Relaxed),
            "received":self.received.load(Ordering::Relaxed).to_string(),"rejected":self.rejected.load(Ordering::Relaxed).to_string(),
            "capacity_dropped":self.capacity_dropped.load(Ordering::Relaxed).to_string(),"expired":self.expired.load(Ordering::Relaxed).to_string(),
            "ack_rejected":self.ack_rejected.load(Ordering::Relaxed).to_string(),"accepted":self.accepted.load(Ordering::Relaxed).to_string(),
            "queued_records":self.queued_records.load(Ordering::Relaxed).to_string(),"queued_bytes":self.queued_bytes.load(Ordering::Relaxed).to_string(),"gaps":self.gaps.load(Ordering::Relaxed)})
    }
    fn add(&self,counter:&AtomicU64,n:u64) {
        if counter.fetch_update(Ordering::Relaxed,Ordering::Relaxed,|old|old.checked_add(n)).is_err() {self.counter_complete.store(false,Ordering::Relaxed);}
    }
    fn dropped(&self)->u64 {
        let values=[&self.rejected,&self.capacity_dropped,&self.expired,&self.ack_rejected];
        values.iter().fold(0u64,|sum,item|sum.saturating_add(item.load(Ordering::Relaxed)))
    }
}
struct Entry {record:DiagnosticRecord,received:Instant}
struct Queue {rows:VecDeque<Entry>,payload_bytes:usize,high:Option<u64>}
impl Queue {
    fn new()->Self {Self {rows:VecDeque::with_capacity(RECORDS),payload_bytes:0,high:None}}
    fn resident(&self)->usize {self.rows.capacity()*std::mem::size_of::<Entry>()+self.payload_bytes}
    fn push(&mut self,record:DiagnosticRecord,stats:&Stats) {
        let expected=self.high.and_then(|value|value.checked_add(1)).unwrap_or(0);
        if record.sequence!=expected {stats.gaps.store(true,Ordering::Relaxed);}
        self.high=Some(self.high.map_or(record.sequence,|high|high.max(record.sequence)));
        if self.rows.len()==RECORDS || record.payload.capacity()>QUEUE_BYTES.saturating_sub(self.resident()) {
            stats.add(&stats.capacity_dropped,1);stats.gaps.store(true,Ordering::Relaxed);return;
        }
        self.payload_bytes+=record.payload.capacity(); self.rows.push_back(Entry {record,received:Instant::now()}); self.publish(stats);
    }
    fn publish(&self,stats:&Stats) {
        stats.queued_records.store(self.rows.len() as u64,Ordering::Relaxed);stats.queued_bytes.store(self.resident() as u64,Ordering::Relaxed);
    }
    fn batch(&mut self,config:&Config,epoch:&str,stats:&Stats)->Result<Option<Pending>,String> {
        while self.rows.front().is_some_and(|row|row.received.elapsed()>=AGE) {
            if let Some(row)=self.rows.pop_front() {self.payload_bytes-=row.record.payload.capacity();stats.add(&stats.expired,1);stats.gaps.store(true,Ordering::Relaxed);}
        }
        if self.rows.is_empty() {self.publish(stats);return Ok(None);}
        let oldest=self.rows.front().ok_or("queue disappeared")?.received;
        let mut records=Vec::with_capacity(128); let mut raw=0usize;
        for _ in 0..128 {
            let Some(front)=self.rows.front() else {break;};
            if records.iter().any(|item:&DiagnosticItem|item.sequence.0==front.record.sequence)
                || front.record.payload.len()>65536usize.saturating_sub(raw) {break;}
            let row=self.rows.pop_front().ok_or("queue disappeared")?;
            self.payload_bytes-=row.record.payload.capacity();raw+=row.record.payload.len();
            let observed_at=match row.record.wall_unix_ns {
                Some(ns)=>{
                    let seconds=i64::try_from(ns/1_000_000_000).map_err(|_|"diagnostic wall range")?;
                    chrono::DateTime::from_timestamp(seconds,(ns%1_000_000_000) as u32).map(|date|date.to_rfc3339_opts(chrono::SecondsFormat::Nanos,true))
                }
                None=>None,
            };
            records.push(DiagnosticItem {sequence:U64(row.record.sequence),monotonic_ns:U64(row.record.monotonic_ns),observed_at,
                record_type:row.record.record_type,payload:crate::hex(&row.record.payload)});
        }
        self.publish(stats); records.sort_unstable_by_key(|record|record.sequence.0);
        let mut batch=DiagnosticBatch {schema_version:1,node_id:config.mapping.node_id.clone(),edge_epoch:epoch.into(),
            process_epoch:config.mapping.process_epoch.clone(),source_id:"consensus_diagnostic".into(),batch_id:"0".repeat(64),
            records,quality:DiagnosticQuality {dropped:U64(stats.dropped()),gaps:stats.gaps.load(Ordering::Relaxed)}};
        batch.batch_id=batch.content_id().map_err(str::to_owned)?;
        let bytes=serde_json::to_vec(&batch).map_err(|e|e.to_string())?;
        DiagnosticBatch::decode(&bytes).map_err(str::to_owned)?;
        // Catalog8's four bytes plus bounded metadata give a tighter measured
        // limit; retain the independent general JSON gate as well.
        if bytes.len()>262144 {return Err("diagnostic JSON expansion".into());}
        Ok(Some(Pending {batch,bytes,oldest,attempts:0,next:Instant::now()}))
    }
}
struct Pending {batch:DiagnosticBatch,bytes:Vec<u8>,oldest:Instant,attempts:u32,next:Instant}
pub async fn run(config:Config,stats:Arc<Stats>,mut stop:tokio::sync::watch::Receiver<bool>)->Result<(),String> {
    let receiver=Receiver::bind(config.mapping.clone())?;
    let transport=Transport::new(&config.destination)?;
    let epoch=crate::hex(&crate::random_token()?);
    let queue=Arc::new(Mutex::new(Queue::new()));
    queue.lock().map_err(|_|"diagnostic queue unavailable")?.publish(&stats);
    stats.counter_complete.store(true,Ordering::Relaxed);stats.running.store(true,Ordering::Relaxed);
    let receiving=queue.clone();let receiving_stats=stats.clone();let mut receiver_stop=stop.clone();
    let receive_task=tokio::spawn(async move {
        let mut tick=tokio::time::interval(Duration::from_millis(5));tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                changed=receiver_stop.changed()=>{if changed.is_err() || *receiver_stop.borrow() {break;}},
                _=tick.tick()=>{
                    for _ in 0..64 {
                        match receiver.receive() {
                            Ok(Received::Empty)=>break,
                            Ok(Received::Handshake)=>{},
                            Ok(Received::Rejected(_))|Err(_)=>{receiving_stats.add(&receiving_stats.rejected,1);receiving_stats.gaps.store(true,Ordering::Relaxed);},
                            Ok(Received::Record(record))=>{
                                receiving_stats.add(&receiving_stats.received,1);
                                if let Ok(mut queue)=receiving.lock() {queue.push(record,&receiving_stats);} else {return Err::<(),String>("diagnostic queue unavailable".into());}
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    });
    let mut pending:Option<Pending>=None;
    let mut tick=tokio::time::interval(Duration::from_millis(250));tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let result:Result<(),String>=async {
        loop {
            tokio::select! {changed=stop.changed()=>{if changed.is_err() || *stop.borrow(){break;}},_=tick.tick()=>{}}
            if receive_task.is_finished() {return Err("diagnostic receiver stopped".into());}
            if pending.is_none() {pending=queue.lock().map_err(|_|"diagnostic queue unavailable")?.batch(&config,&epoch,&stats)?;}
            let Some(batch)=pending.as_mut() else {continue;};
            if batch.oldest.elapsed()>=AGE || batch.attempts>=8 {
                stats.add(&stats.expired,batch.batch.records.len() as u64);stats.gaps.store(true,Ordering::Relaxed);pending=None;continue;
            }
            if Instant::now()<batch.next {continue;}
            batch.attempts+=1;
            let response=tokio::select! {
                response=transport.post(&batch.bytes)=>response,
                changed=stop.changed()=>{if changed.is_err() || *stop.borrow(){break;} else {continue;}},
            };
            match response {
                Ok((200,body))=>{
                    let ack=serde_json::from_slice::<Ack>(&body).map_err(|_|"invalid diagnostic ACK");
                    let last=batch.batch.records.last().ok_or("empty pending batch")?.sequence.0;
                    if ack.is_ok_and(|ack|ack.batch_id==batch.batch.batch_id && ack.accepted_through_sequence.0==last && ack.duplicate_count.0<=batch.batch.records.len() as u64) {
                        stats.add(&stats.accepted,batch.batch.records.len() as u64);pending=None;
                    } else {stats.add(&stats.ack_rejected,batch.batch.records.len() as u64);stats.gaps.store(true,Ordering::Relaxed);pending=None;}
                }
                Ok((400|409|413, _))=>{stats.add(&stats.ack_rejected,batch.batch.records.len() as u64);stats.gaps.store(true,Ordering::Relaxed);pending=None;}
                _=>{batch.next=Instant::now()+Duration::from_millis((250u64<<batch.attempts.min(5)).min(8000));}
            }
        }
        Ok(())
    }.await;
    receive_task.abort();let _=receive_task.await;
    stats.running.store(false,Ordering::Relaxed);
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    fn config()->Config {
        Config {mapping:Mapping {socket_path:"/tmp/unused".into(),node_id:"node_a".into(),native_pid:1,native_uid:0,native_gid:0,process_epoch:"23".repeat(16)},
            destination:Destination {origin:"https://localhost:1/".into(),ca_file:"unused".into(),identity_file:"unused".into(),token_file:"unused".into()}}
    }
    fn record(sequence:u64)->DiagnosticRecord {
        DiagnosticRecord {record_type:1,source_catalog_id:8,epoch:[0x23;16],sequence,monotonic_ns:sequence,wall_unix_ns:None,payload:vec![1,0,3,0]}
    }
    #[test]
    fn bounded_queue_and_json_have_separate_accounting() {
        let stats=Stats::default();let mut queue=Queue::new();
        for sequence in 0..4097 {queue.push(record(sequence),&stats);}
        assert_eq!(queue.rows.len(),4096);assert_eq!(stats.capacity_dropped.load(Ordering::Relaxed),1);
        assert!(queue.resident()<QUEUE_BYTES);
        let batch=queue.batch(&config(),"edge_a",&stats).unwrap().unwrap();
        assert_eq!(batch.batch.records.len(),128);assert_eq!(batch.batch.records.iter().map(|item|item.payload.len()/2).sum::<usize>(),512);
        assert!(batch.bytes.len()<262144);assert_eq!(queue.rows.len(),3968);
        assert_eq!(batch.batch.content_id().unwrap(),batch.batch.batch_id);
        // Independently parse the emitted body; the producer is no substitute
        // for the receiver's JSON and catalog boundary checks.
        assert_eq!(DiagnosticBatch::decode(&batch.bytes).unwrap().records.len(),128);
        let mut hostile=batch.batch.clone();hostile.records[0].payload="ff".repeat(65537);
        assert_eq!(DiagnosticBatch::decode(&serde_json::to_vec(&hostile).unwrap()).unwrap_err(),"decoded payload limit");
        assert_eq!(DiagnosticBatch::decode(&vec![b' ';262145]).unwrap_err(),"JSON body limit");
    }
    #[test]
    fn late_sequence_crosses_flush_boundary_and_original_age_is_not_renewed() {
        let stats=Stats::default();let mut queue=Queue::new();
        queue.push(record(10),&stats);let first=queue.batch(&config(),"edge_a",&stats).unwrap().unwrap();
        queue.push(record(0),&stats);let late=queue.batch(&config(),"edge_a",&stats).unwrap().unwrap();
        assert_eq!(first.batch.records[0].sequence.0,10);assert_eq!(late.batch.records[0].sequence.0,0);
        assert!(late.batch.quality.gaps);
        queue.push(record(11),&stats);queue.rows.front_mut().unwrap().received=Instant::now()-Duration::from_secs(31);
        assert!(queue.batch(&config(),"edge_a",&stats).unwrap().is_none());
        assert_eq!(stats.expired.load(Ordering::Relaxed),1);
        assert!(first.oldest<=late.oldest);
    }
}
