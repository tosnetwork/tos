// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! A reservation is durable before signing; a send permit is consumed before I/O.
use anyhow::{ensure, Result};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::path::Path;

pub struct Store(Connection);
#[derive(Debug, PartialEq, Eq)]
pub struct Lease {
    pub request: String,
    pub binding: String,
    pub sequence: u32,
    pub message: Option<Vec<u8>>,
    pub fresh: bool,
}
impl Store {
    pub fn create(path: &Path, scope: &str) -> Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        Self::open_inner(path, scope, true)
    }
    pub fn open(path: &Path, scope: &str) -> Result<Self> {
        Self::open_inner(path, scope, false)
    }
    fn open_inner(path: &Path, scope: &str, initialize: bool) -> Result<Self> {
        // The containing private directory is checked by the operator boundary.
        // Refuse aliases even for an existing SQLite file.
        if path.exists() {
            use std::os::unix::fs::MetadataExt;
            let m = std::fs::symlink_metadata(path)?;
            let uid = unsafe { libc::geteuid() };
            ensure!(
                m.is_file() && m.nlink() == 1 && m.uid() == uid && m.mode() & 0o077 == 0,
                "unsafe lease database"
            );
        } else {
            anyhow::bail!("lease database missing; implicit custody reset refused");
        }
        let mut c = Connection::open(path)?;
        c.busy_timeout(std::time::Duration::from_secs(2))?;
        if !initialize {
            let existing: Option<String> =
                c.query_row("SELECT scope FROM metadata", [], |r| r.get(0)).optional()?;
            ensure!(
                existing.as_deref() == Some(scope),
                "lease metadata missing or changed; implicit reset refused"
            );
        }
        c.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA max_page_count=4096;
          CREATE TABLE IF NOT EXISTS metadata(scope TEXT PRIMARY KEY);
          CREATE TABLE IF NOT EXISTS leases(request TEXT PRIMARY KEY,binding TEXT NOT NULL,sequence INTEGER NOT NULL,live INTEGER NOT NULL DEFAULT 1,sent INTEGER NOT NULL DEFAULT 0,message BLOB,record BLOB,slot INTEGER UNIQUE);
          CREATE UNIQUE INDEX IF NOT EXISTS live_sequence ON leases(sequence) WHERE live=1;
          CREATE TABLE IF NOT EXISTS permits(token TEXT PRIMARY KEY,request TEXT NOT NULL REFERENCES leases(request),message_hash TEXT NOT NULL,expires INTEGER NOT NULL,used INTEGER NOT NULL DEFAULT 0);
          CREATE TABLE IF NOT EXISTS fee_notes(transaction_hash TEXT NOT NULL,leaf INTEGER NOT NULL,note_body TEXT NOT NULL,receipt BLOB NOT NULL,payload BLOB NOT NULL,PRIMARY KEY(transaction_hash,leaf),UNIQUE(note_body));
          CREATE TABLE IF NOT EXISTS quote_claims(quote_hash TEXT PRIMARY KEY,request TEXT NOT NULL UNIQUE REFERENCES leases(request));")?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if initialize {
            tx.execute("INSERT INTO metadata VALUES(?1)", [scope])?;
        }
        let scopes: Vec<String> = tx
            .prepare("SELECT scope FROM metadata")?
            .query_map([], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        ensure!(scopes == [scope], "lease release mismatch");
        tx.commit()?;
        Ok(Self(c))
    }
    pub fn reserve(&mut self, request: &str, binding: &str, sequence: u32) -> Result<Lease> {
        let tx = self.0.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prior = tx
            .query_row(
                "SELECT request,binding,sequence,message FROM leases WHERE request=?1",
                [request],
                |r| {
                    Ok(Lease {
                        request: r.get(0)?,
                        binding: r.get(1)?,
                        sequence: r.get(2)?,
                        message: r.get(3)?,
                        fresh: false,
                    })
                },
            )
            .optional()?;
        let lease = if let Some(prior) = prior {
            ensure!(
                prior.binding == binding && prior.sequence == sequence,
                "lease replay binding mismatch"
            );
            prior
        } else {
            let count: i64 = tx.query_row("SELECT count(*) FROM leases", [], |r| r.get(0))?;
            ensure!(count < 32, "lease history full; drain and rotate custody");
            tx.execute(
                "INSERT INTO leases(request,binding,sequence) VALUES(?1,?2,?3)",
                params![request, binding, sequence],
            )?;
            Lease {
                request: request.into(),
                binding: binding.into(),
                sequence,
                message: None,
                fresh: true,
            }
        };
        tx.commit()?;
        Ok(lease)
    }
    pub fn persist_message(&mut self, request: &str, message: &[u8]) -> Result<()> {
        ensure!(!message.is_empty() && message.len() <= 512 * 1024, "message byte bound");
        let tx = self.0.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<Vec<u8>> =
            tx.query_row("SELECT message FROM leases WHERE request=?1", [request], |r| r.get(0))?;
        if let Some(existing) = existing {
            ensure!(existing == message, "immutable signed message mismatch");
        } else {
            tx.execute("UPDATE leases SET message=?2 WHERE request=?1", params![request, message])?;
        }
        tx.commit()?;
        Ok(())
    }
    pub fn lookup(&self, request: &str) -> Result<Option<Lease>> {
        Ok(self
            .0
            .query_row(
                "SELECT request,binding,sequence,message FROM leases WHERE request=?1",
                [request],
                |r| {
                    Ok(Lease {
                        request: r.get(0)?,
                        binding: r.get(1)?,
                        sequence: r.get(2)?,
                        message: r.get(3)?,
                        fresh: false,
                    })
                },
            )
            .optional()?)
    }
    pub fn bind_slot(&mut self, request: &str, slot: u64) -> Result<()> {
        ensure!(slot > 0 && slot <= i64::MAX as u64, "acceptance slot bound");
        let tx = self.0.transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure!(
            tx.execute(
                "UPDATE leases SET slot=?2 WHERE request=?1 AND (slot IS NULL OR slot=?2)",
                params![request, slot]
            )? == 1,
            "acceptance slot binding mismatch"
        );
        tx.commit()?;
        Ok(())
    }
    pub fn claim_quote(&mut self, request: &str, quote: &str) -> Result<()> {
        let tx = self.0.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("INSERT OR IGNORE INTO quote_claims VALUES(?1,?2)", params![quote, request])?;
        let owner: Option<String> = tx
            .query_row("SELECT request FROM quote_claims WHERE quote_hash=?1", [quote], |r| {
                r.get(0)
            })
            .optional()?;
        ensure!(owner.as_deref() == Some(request), "quote already bound to another native request");
        tx.commit()?;
        Ok(())
    }
    pub fn assert_claimable(&self, request: &str, quote: &str, slot: u64) -> Result<()> {
        ensure!(slot > 0 && slot <= i64::MAX as u64, "acceptance slot bound");
        let quote_owner: Option<String> = self
            .0
            .query_row("SELECT request FROM quote_claims WHERE quote_hash=?1", [quote], |r| {
                r.get(0)
            })
            .optional()?;
        let slot_owner: Option<String> = self
            .0
            .query_row("SELECT request FROM leases WHERE slot=?1", [slot], |r| r.get(0))
            .optional()?;
        ensure!(
            quote_owner.as_deref().is_none_or(|owner| owner == request)
                && slot_owner.as_deref().is_none_or(|owner| owner == request),
            "native quote/slot already claimed"
        );
        Ok(())
    }
    pub fn import_fee(
        &mut self,
        transaction: &str,
        leaf: u64,
        note_body: &str,
        receipt: &[u8],
        payload: &[u8],
    ) -> Result<()> {
        ensure!(receipt.len() <= 16384 && payload.len() == 1233, "fee import byte bound");
        let tx = self.0.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count: i64 = tx.query_row("SELECT count(*) FROM fee_notes", [], |r| r.get(0))?;
        let prior:Option<(Vec<u8>,Vec<u8>,String)>=tx.query_row("SELECT receipt,payload,note_body FROM fee_notes WHERE transaction_hash=?1 AND leaf=?2",params![transaction,leaf],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        if let Some((old_receipt, old_payload, old_body)) = prior {
            // Later checkpoints may attest the same finalized note. The
            // economic identity and ciphertext remain immutable.
            ensure!(
                old_payload == payload && old_body == note_body && !old_receipt.is_empty(),
                "conflicting fee import"
            );
        } else {
            ensure!(count < 32, "fee note history full");
            tx.execute(
                "INSERT INTO fee_notes VALUES(?1,?2,?3,?4,?5)",
                params![transaction, leaf, note_body, receipt, payload],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
    pub fn record(&self, request: &str) -> Result<Vec<u8>> {
        Ok(self
            .0
            .query_row("SELECT record FROM leases WHERE request=?1", [request], |r| r.get(0))?)
    }
    pub fn persist_prepared(&mut self, request: &str, message: &[u8], record: &[u8]) -> Result<()> {
        ensure!(
            !message.is_empty()
                && message.len() <= 512 * 1024
                && !record.is_empty()
                && record.len() <= 65536,
            "prepared byte bounds"
        );
        let tx = self.0.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed=tx.execute("UPDATE leases SET message=?2,record=?3 WHERE request=?1 AND message IS NULL AND record IS NULL AND sent=0",params![request,message,record])?;
        ensure!(changed == 1, "prepared record already signed");
        tx.commit()?;
        Ok(())
    }
    pub fn permit(
        &mut self,
        request: &str,
        token: &str,
        message_hash: &str,
        now: u64,
    ) -> Result<()> {
        let expiry = now.checked_add(5).ok_or_else(|| anyhow::anyhow!("permit expiry overflow"))?;
        let tx = self.0.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let message: Option<Vec<u8>> = tx.query_row(
            "SELECT message FROM leases WHERE request=?1 AND live=1 AND sent=0",
            [request],
            |r| r.get(0),
        )?;
        let message = message.ok_or_else(|| anyhow::anyhow!("unsigned lease"))?;
        ensure!(crate::protocol::hash(&message) == message_hash, "permit message mismatch");
        let count: i64 = tx.query_row("SELECT count(*) FROM permits", [], |r| r.get(0))?;
        ensure!(count < 64, "permit history full");
        tx.execute(
            "INSERT INTO permits(token,request,message_hash,expires) VALUES(?1,?2,?3,?4)",
            params![token, request, message_hash, expiry],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn consume(&mut self, token: &str, message: &[u8], now: u64) -> Result<()> {
        let tx = self.0.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed=tx.execute("UPDATE permits SET used=1 WHERE token=?1 AND used=0 AND expires>=?2 AND message_hash=?3 AND request IN(SELECT request FROM leases WHERE live=1 AND sent=0)",params![token,now,crate::protocol::hash(message)])?;
        ensure!(changed == 1, "permit expired, mismatched or already consumed");
        let marked=tx.execute("UPDATE leases SET sent=1 WHERE request=(SELECT request FROM permits WHERE token=?1) AND sent=0",[token])?;
        ensure!(marked == 1, "lease already submitted");
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quotes_cannot_authorize_two_native_requests() -> Result<()> {
        let d = tempfile::tempdir()?;
        let p = d.path().join("leases.db");
        let mut s = Store::create(&p, "scope")?;
        s.reserve("one", "binding", 1)?;
        s.claim_quote("one", "quote")?;
        drop(s);
        let mut s = Store::open(&p, "scope")?;
        s.claim_quote("one", "quote")?;
        s.reserve("two", "binding", 2)?;
        assert!(s.claim_quote("two", "quote").is_err());
        assert!(s.claim_quote("one", "changed quote").is_err());
        s.claim_quote("two", "another quote")?;
        Ok(())
    }
    #[test]
    fn reopen_reserves_sequence_and_keeps_exact_bytes() -> Result<()> {
        let d = tempfile::tempdir()?;
        let path = d.path().join("leases.db");
        let mut s = Store::create(&path, "scope")?;
        s.reserve("request", "binding", 7)?;
        assert!(s.reserve("other", "binding", 7).is_err());
        assert!(s.reserve("request", "changed", 7).is_err());
        s.persist_message("request", b"signed bytes")?;
        drop(s);
        let mut s = Store::open(&path, "scope")?;
        assert_eq!(s.reserve("request", "binding", 7)?.message, Some(b"signed bytes".to_vec()));
        assert!(s.persist_message("request", b"new signature").is_err());
        assert!(Store::open(&path, "other scope").is_err());
        Ok(())
    }
    #[test]
    fn send_permit_is_one_use_even_after_restart() -> Result<()> {
        let d = tempfile::tempdir()?;
        let path = d.path().join("leases.db");
        let mut s = Store::create(&path, "scope")?;
        s.reserve("request", "binding", 7)?;
        s.persist_message("request", b"message")?;
        s.permit("request", "token", &crate::protocol::hash(b"message"), 100)?;
        assert!(s.consume("token", b"other", 101).is_err());
        s.permit("request", "expired", &crate::protocol::hash(b"message"), 100)?;
        assert!(s.consume("expired", b"message", 106).is_err());
        s.permit("request", "second", &crate::protocol::hash(b"message"), 100)?;
        s.consume("token", b"message", 101)?;
        drop(s);
        let mut s = Store::open(&path, "scope")?;
        assert!(s.consume("token", b"message", 102).is_err());
        assert!(s.consume("second", b"message", 102).is_err());
        assert!(s.permit("request", "third", &crate::protocol::hash(b"message"), 102).is_err());
        Ok(())
    }
    #[test]
    fn slots_and_interrupted_reservations_survive_restart() -> Result<()> {
        let d = tempfile::tempdir()?;
        let p = d.path().join("leases.db");
        let mut s = Store::create(&p, "scope")?;
        assert!(s.reserve("one", "binding", 1)?.fresh);
        s.bind_slot("one", 1)?;
        drop(s);
        let mut s = Store::open(&p, "scope")?;
        let interrupted = s.reserve("one", "binding", 1)?;
        assert!(!interrupted.fresh && interrupted.message.is_none());
        s.reserve("two", "binding", 2)?;
        assert!(s.bind_slot("two", 1).is_err());
        assert!(s.bind_slot("one", 2).is_err());
        s.bind_slot("two", 2)?;
        Ok(())
    }
    #[test]
    fn missing_database_cannot_reset_custody() -> Result<()> {
        let d = tempfile::tempdir()?;
        let p = d.path().join("leases.db");
        assert!(Store::open(&p, "scope").is_err());
        let s = Store::create(&p, "scope")?;
        drop(s);
        std::fs::remove_file(&p)?;
        assert!(Store::open(&p, "scope").is_err());
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&p)?;
        assert!(Store::open(&p, "scope").is_err());
        Ok(())
    }
    #[test]
    fn finalized_fee_import_is_idempotent_and_conflicts_refuse() -> Result<()> {
        let d = tempfile::tempdir()?;
        let mut s = Store::create(&d.path().join("leases.db"), "scope")?;
        let payload = vec![7; 1233];
        s.import_fee("transaction", 3, "note", b"checkpoint one", &payload)?;
        s.import_fee("transaction", 3, "note", b"checkpoint two", &payload)?;
        let count: i64 = s.0.query_row("SELECT count(*) FROM fee_notes", [], |r| r.get(0))?;
        assert_eq!(count, 1);
        assert!(s.import_fee("transaction", 3, "changed note", b"receipt", &payload).is_err());
        assert!(s.import_fee("transaction", 3, "note", b"receipt", &vec![8; 1233]).is_err());
        assert!(s.import_fee("other transaction", 4, "note", b"receipt", &payload).is_err());
        Ok(())
    }
    #[test]
    fn history_is_bounded_and_old_reservations_remain() -> Result<()> {
        let d = tempfile::tempdir()?;
        let mut s = Store::create(&d.path().join("leases.db"), "scope")?;
        for i in 0..32 {
            s.reserve(&format!("request-{i}"), "binding", i)?;
        }
        assert!(s.reserve("overflow", "binding", 32).is_err());
        assert!(!s.reserve("request-0", "binding", 0)?.fresh);
        Ok(())
    }
}
