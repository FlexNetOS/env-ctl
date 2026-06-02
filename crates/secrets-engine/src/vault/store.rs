//! Storage backend behind a `Store` trait. OI-1 RESOLVED = libSQL (NEW-3, see docs/SERVER-MODE.md):
//! its server/replica/sync serves remote clients. libSQL + its bundled C SQLite (`libsql-ffi`) are
//! QUARANTINED in `crates/secrets-store-libsql`, consumed ONLY by secretd behind THIS trait — the
//! engine lib NEVER links libSQL, so the per-crate no-C gate
//! (`! cargo tree -p envctl-secrets-engine | grep libsql-ffi`) stays green. Encryption happens ABOVE
//! this trait (ciphertext + non-secret metadata only). Phase 0 ships only `InMemStore`; the libSQL
//! backend lands in Phase 1 in the store crate, C-isolated.
#[cfg(not(feature = "inmem-store"))]
compile_error!("select a store backend feature (`inmem-store`, or the OI-1-ruled pure-Rust backend)");

use crate::event::AuditRecord;

/// The vault's persistence surface. Encryption happens ABOVE this trait — a `Store` only ever
/// sees ciphertext + non-secret metadata. The durable, hash-chained audit log is committed here
/// before security RPCs return (HF-14).
pub trait Store: Send + Sync {
    fn get_meta(&self, k: &str) -> anyhow::Result<Option<String>>;
    fn put_meta(&self, k: &str, v: &str) -> anyhow::Result<()>;
    fn append_audit(&self, rec: &AuditRecord) -> anyhow::Result<i64>;
    fn verify_audit_chain(&self) -> anyhow::Result<()>;
    // secrets / keyslots / relay / ca CRUD — full set in Phase 1.
}

/// RAM-only backend for tests/CI (the envctl `DryRunRunner` analogue). Holds nothing durable.
pub struct InMemStore;

impl Store for InMemStore {
    fn get_meta(&self, _k: &str) -> anyhow::Result<Option<String>> {
        todo!()
    }
    fn put_meta(&self, _k: &str, _v: &str) -> anyhow::Result<()> {
        todo!()
    }
    fn append_audit(&self, _rec: &AuditRecord) -> anyhow::Result<i64> {
        todo!()
    }
    fn verify_audit_chain(&self) -> anyhow::Result<()> {
        todo!()
    }
}
