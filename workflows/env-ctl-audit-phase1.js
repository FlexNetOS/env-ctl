export const meta = {
  name: 'env-ctl-audit-phase1',
  description: 'Independent fresh-eyes security audit of the committed crypto core + functional vault; 8 lenses -> one prioritized AUDIT doc',
  phases: [
    { title: 'Audit', detail: '8 parallel auditors, one security lens each (read-only)' },
    { title: 'Synthesize', detail: 'dedup + prioritize into docs/audits/AUDIT-phase1.md' },
  ],
}

const REPO = '/home/drdave/Desktop/env-ctl'
const ENG = REPO + '/crates/secrets-engine/src'
const CTX = 'env-ctl is a pure-Rust local-+server secrets vault + credential broker. AUDIT TARGET = the COMMITTED, building code (54 tests green): ' +
  ENG + '/vault/crypto.rs (XChaCha20-Poly1305 seal/open), vault/aad.rs (canonical AAD), keyslot.rs (argon2id/HKDF dual-KEK keyslots, wrap/unwrap, header MAC), vault/audit.rs (hash chain), vault/store.rs (Store trait + InMemStore), lib.rs (Engine init_vault/unlock/lock/secret_put/secret_get + audit-head anchor), event.rs/error.rs/guard.rs. Cross-reference ' + REPO + '/docs/THREAT-MODEL.md (FS-S*/REQ-SEC-*), docs/DESIGN-NOTES.md (HF-*/CF-*/OI-*), and docs/research/ (01 AEAD, 02 keyslots, 13 audit). This is READ-ONLY: do NOT modify code; report findings. Be a skeptic — a secrets vault must assume a determined local attacker, a stolen disk/backup, and malformed/adversarial stored bytes. Cite file:line.'

const FIND = {
  type: 'object', additionalProperties: false,
  properties: {
    lens: { type: 'string' },
    overall: { type: 'string', description: 'one-paragraph verdict for this lens' },
    findings: { type: 'array', items: { type: 'object', additionalProperties: false, properties: {
      severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
      title: { type: 'string' }, location: { type: 'string', description: 'file:line(s)' },
      issue: { type: 'string' }, impact: { type: 'string' }, fix: { type: 'string' },
      confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
    }, required: ['severity', 'title', 'location', 'issue', 'fix', 'confidence'] } },
  },
  required: ['lens', 'overall', 'findings'],
}

const LENSES = [
  'AEAD usage: XChaCha20-Poly1305 nonce generation (OsRng, 24-byte, never reused/seeded outside tests), AAD authenticated-not-encrypted + bound to record identity on BOTH seal and open, full 16-byte tag, tag-as-sole-oracle, in-place vs allocating buffers leaking plaintext copies.',
  'KDF + keyslots: argon2id params + the 256MiB/t floors + downgrade guard, HKDF for the USB slot (domain-sep info), the dual-KEK LUKS-style design (1-of-2 OR semantics + the documented weaker-factor floor), wrap/unwrap AAD binding to slot metadata, RequireBoth correctness.',
  'Key material in RAM: Dek/Kek zeroization (ZeroizeOnDrop, consume-by-value), no Serialize on key types, lock() truly zeroizes the live DEK, the broker hmac_key + audit-head key derivation, heap reallocation/copies that escape zeroization, secrets crossing the engine boundary.',
  'Audit chain: row_hash = H(prev||canonical(row)) canonicalization (fixed-width/JCS), genesis anchor, gap-free monotonic seq, the DEK-keyed audit-HEAD anchor vs a store-level truncate-and-relink, reorder/tamper detection, HF-14 durable-before-return, what an attacker who controls the store can still forge.',
  'Vault state machine: init/unlock/lock transitions, unlock-failure is a single generic error (no which-slot oracle), header-MAC verified on unlock + refuse on drift/floor-regression, secret_get reveal apply-gating + broker_only refusal, no DEK exposure on any path, re-init refusal.',
  'Store boundary + data integrity: prove the Store NEVER sees a DEK/plaintext/unlock-key; the row_id reservation TOCTOU fix actually closes the AAD/row_id divergence; version monotonicity; serialization of any secret-bearing type; what a malicious Store impl could do (it is in the TCB or not?).',
  'Panic-safety on adversarial input: can attacker-controlled stored bytes (bad nonce len, truncated ct, corrupt keyslot, malformed audit row, huge length prefix) panic/abort the engine instead of returning None/Err? unwrap/expect/slice-index/from_slice on data-derived values; integer overflow in seq/version/ttl; DoS via huge inputs.',
  'Fail-closed + forbidden-states conformance: walk the implemented code against THREAT-MODEL FS-S* / REQ-SEC-* and DESIGN-NOTES invariants — list each invariant as UPHELD / VIOLATED / NOT-YET-APPLICABLE with evidence (esp. real-key-never-in-event/audit/err, vault-never-plaintext, dry-run defaults, refuse-on-ambiguity).',
]

phase('Audit')
log('8 independent auditors reviewing the committed crypto + vault...')
const audits = (await parallel(LENSES.map((lens, i) => () =>
  agent(CTX + '\n\nYOUR LENS:\n' + lens + '\n\nRead the relevant files, then report your verdict + findings (each with file:line, impact, and a concrete fix). If the code is sound on your lens, say so with info/low notes — do not invent issues.',
    { label: 'audit:' + i, phase: 'Audit', agentType: 'Explore', schema: FIND })
))).filter(Boolean)

phase('Synthesize')
const total = audits.reduce((n, a) => n + (a.findings ? a.findings.length : 0), 0)
log('Synthesizing ' + total + ' findings across 8 lenses into AUDIT-phase1.md...')
const out = await agent(
  'You are the lead security auditor. Dedup + reconcile the 8 lens reports below into ONE prioritized audit. WRITE it to ' + REPO + '/docs/audits/AUDIT-phase1.md (create the dir): an executive verdict (is the Phase-1 crypto+vault sound for a secrets vault?), a severity-sorted findings table (severity · title · location · impact · fix · confidence), per-invariant conformance (UPHELD/VIOLATED/N-A), and a "must-fix before Phase-1 sign-off" shortlist. Be precise and honest — distinguish real defects from hardening nits. After writing, RETURN {summary, critical_count, high_count, must_fix:[titles], doc_path}.\n\n' + CTX + '\n\nLENS REPORTS (JSON):\n' + JSON.stringify(audits),
  { label: 'synth-audit', phase: 'Synthesize' })

log('AUDIT-phase1.md written.')
return out