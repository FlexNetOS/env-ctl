export const meta = {
  name: 'env-ctl-phase1b-vault',
  description: 'Make the vault functional: real InMemStore + Engine init/unlock/lock/secret_put/secret_get over keyslots+AEAD + tamper-evident audit chain, with integration tests',
  phases: [
    { title: 'Design', detail: 'lock the Store-trait + Engine state-machine contracts' },
    { title: 'Implement', detail: 'one implementer wires the functional vault end-to-end' },
    { title: 'Review', detail: '3 adversarial reviewers (state machine, crypto, audit/zeroize)' },
    { title: 'Fix', detail: 'fold confirmed fixes' },
  ],
}

const REPO = '/home/drdave/Desktop/env-ctl'
const ENG = REPO + '/crates/secrets-engine'
const RULES = [
  'Engine = ' + ENG + ' (lib `envctl_secrets`). PURE RUST, stable, MSRV 1.80, async-free, NEVER prints (emits SecretEvent). Deps already present: chacha20poly1305 0.10 (alloc,getrandom,rand_core), argon2 0.5, hkdf 0.12, sha2 0.10, blake3 1.5, zeroize 1.8, subtle 2.6, rand 0.8, getrandom 0.2, serde, serde_json, toml, anyhow, thiserror, chrono. DO NOT add deps. MACs = blake3::keyed_hash; ct-compare = subtle.',
  'ALREADY IMPLEMENTED + tested (reuse, do not rewrite): vault/crypto.rs seal/open; vault/aad.rs record_aad + TableTag; keyslot.rs keyslot_aad/wrap_dek/unwrap_dek/kek_from_usb/kek_from_passphrase/header_mac + Dek/Kek/Keyslot/Factor/Kdf/Argon2Params/ARGON2_M_KIB_FLOOR; broker/token.rs verify_bearer/mac_bearer.',
  'PRESERVE the PUBLIC METHOD NAMES + semantics of Engine (unlock/lock/secret_put/secret_get/relay_*/ca_*/run_child) and the SecretEvent/EngineError/VaultState types + the 4 seam traits. You MAY: add a store field to EngineInner; add a `store` param to Engine::with_seams; ADD an init path (e.g. Engine::init_vault) to create the DEK + enroll keyslots; expand the Store trait; add a new module (declare its `pub mod` in lib.rs). Keep ALL existing tests (lib unit tests + tests/phase0.rs) PASSING.',
  'Encryption happens ABOVE the Store: a Store only ever sees ciphertext + non-secret metadata (no DEK, no plaintext, no unlock key). The DEK lives only in Vault::Unlocked and is zeroized on lock(). Audit rows for security ops are appended DURABLY (in InMemStore: synchronously) BEFORE the op returns (HF-14).',
].join('\n')

const DESIGN_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    store_trait: { type: 'string', description: 'the EXACT expanded Store trait (method signatures) covering: meta KV, secrets (put/get-by-name/list/versions), keyslots (load/save/list), audit (append/verify/query), relay policies+bearers (stub ok), ca/certs (stub ok). Real CRUD for meta/secrets/keyslots/audit; relay/ca may be minimal stubs returning empty.' },
    engine_state: { type: 'string', description: 'the Engine vault state machine: init_vault (create DEK + passphrase keyslot + optional USB keyslot, persist header MAC), unlock(Usb|Passphrase) (derive KEK, unwrap DEK from a matching keyslot, verify header MAC, set Unlocked), lock (zeroize DEK), secret_put (seal under DEK with record_aad, version, store), secret_get (load, open, reveal-gated). Exact signatures + the EngineInner additions (store field).' },
    audit_api: { type: 'string', description: 'the audit hash-chain helper: canonical row encoding + row_hash = blake3(prev_hash || canonical(row)) (or sha2), genesis, verify_chain. Where it lives (new module name + lib.rs decl).' },
    test_plan: { type: 'string', description: 'integration tests proving: init+passphrase-unlock+put+get round-trip; USB-keyslot unlock via a fake UsbProbe; wrong passphrase fails; lock zeroizes (subsequent get refused); audit chain verifies + detects a tampered row; the existing phase0 tests still pass.' },
  },
  required: ['store_trait', 'engine_state', 'audit_api', 'test_plan'],
}

const FIND = {
  type: 'object', additionalProperties: false,
  properties: { lens: { type: 'string' }, findings: { type: 'array', items: { type: 'object', additionalProperties: false, properties: {
    severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low'] }, issue: { type: 'string' }, fix: { type: 'string' }, confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
  }, required: ['severity', 'issue', 'fix', 'confidence'] } } },
  required: ['lens', 'findings'],
}

phase('Design')
log('Designing the functional-vault contracts...')
const design = await agent(
  'Design the Phase-1b FUNCTIONAL vault for env-ctl. Read the current engine source under ' + ENG + '/src/ (lib.rs, vault/*, keyslot.rs, broker/*, event.rs, error.rs, guard.rs) so your contracts fit the EXISTING types. Produce the contracts per schema — exact, buildable signatures that reuse the already-implemented crypto/keyslot/aad/token functions. The default deployment store for Phase 1b is the RAM-backed InMemStore (interior mutability); the libSQL store is a later crate behind the SAME trait.\n\n' + RULES,
  { label: 'design', phase: 'Design', schema: DESIGN_SCHEMA })

phase('Implement')
log('Implementing the functional vault end-to-end (single implementer for the interdependent core)...')
const impl = await agent(
  'Implement the Phase-1b functional vault per the DESIGN below. You own the whole interdependent core, so write it as ONE coherent change across these files (Read each first, then Write):\n' +
  '- ' + ENG + '/src/vault/store.rs (expand Store trait + REAL RAM-backed InMemStore with interior mutability + InMemStore::new())\n' +
  '- ' + ENG + '/src/lib.rs (implement Engine::init_vault/open/with_seams/unlock/lock/secret_put/secret_get; add the store field to EngineInner; declare any new module)\n' +
  '- ' + ENG + '/src/vault/mod.rs (Vault state helpers if needed)\n' +
  '- a NEW audit module (e.g. ' + ENG + '/src/audit.rs) for the hash chain, declared `pub mod audit;` in lib.rs\n' +
  'Add the integration tests from the design (as ' + ENG + '/tests/vault.rs). Keep tests/phase0.rs + all lib unit tests passing. Engine stays async-free + never prints.\n\n' +
  'DESIGN (JSON):\n' + JSON.stringify(design) + '\n\n' + RULES,
  { label: 'implement', phase: 'Implement' })

phase('Review')
log('3 adversarial reviewers auditing the functional vault...')
const LENSES = [
  'vault state machine + Store boundary: are init/unlock/lock transitions correct and fail-closed? Is the DEK EVER exposed to the Store or serialized? Does lock() truly zeroize and does a post-lock secret_get refuse? Does wrong-passphrase/wrong-USB unlock fail cleanly (generic error, no oracle)? Is the header MAC verified on unlock and refused on drift?',
  'crypto correctness end-to-end: is record_aad bound correctly per secret/version/dek_generation on both seal and open? Are keyslots wrapped/unwrapped with the right AAD? Any nonce reuse, any KEK/DEK left un-zeroized, any panic path reachable by bad stored data (must be Option/Err, not panic)?',
  'audit chain + durability: is row_hash = H(prev||canonical(row)) canonical + gap-free seq? Does verify detect tamper/truncation/reorder? Are security-op audit rows appended BEFORE the op returns (HF-14)? Plus: will it COMPILE on the pinned versions, and do all existing tests still pass?',
]
const reviews = (await parallel(LENSES.map((lens, i) => () =>
  agent('Adversarially review the env-ctl Phase-1b functional vault through ONE lens:\n' + lens + '\nRead the implemented files under ' + ENG + '/src/ + ' + ENG + '/tests/vault.rs. Concrete flaws + concrete fixes; default to reporting when uncertain.\n\nIMPLEMENT NOTES:\n' + impl,
    { label: 'review:' + i, phase: 'Review', schema: FIND })
))).filter(Boolean)

phase('Fix')
log('Folding confirmed fixes...')
const fixed = await agent(
  'Finalize the env-ctl Phase-1b vault: read the files + the review findings below, APPLY all confirmed critical/high/medium fixes (Edit/Write), and ensure the engine compiles on stable with the pinned deps and ALL tests pass (lib unit + tests/phase0.rs + tests/vault.rs). Preserve public method names. MACs=blake3::keyed_hash, ct-compare=subtle, no new deps, async-free.\nFiles: ' + ENG + '/src/{lib.rs,audit.rs,vault/store.rs,vault/mod.rs} + ' + ENG + '/tests/vault.rs.\n\nFINDINGS (JSON):\n' + JSON.stringify(reviews) + '\n\n' + RULES,
  { label: 'fix', phase: 'Fix' })

log('Phase-1b functional vault implemented + reviewed + fixed.')
return { design, impl, reviews, fixed }