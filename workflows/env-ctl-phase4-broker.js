export const meta = {
  name: 'env-ctl-phase4-broker',
  description: 'Implement the credential broker: pure decide(), relay mint/revoke, async relay_swap, real InMemStore relay CRUD, with tests',
  phases: [
    { title: 'Design', detail: 'lock the bearer format, Broker state, decide() truth table, swap flow' },
    { title: 'Implement', detail: 'one implementer wires the broker end-to-end' },
    { title: 'Review', detail: '3 adversarial reviewers (decide/forgery, swap/key-exposure, mint/gating)' },
    { title: 'Fix', detail: 'fold confirmed fixes' },
  ],
}

const REPO = '/home/drdave/Desktop/env-ctl'
const ENG = REPO + '/crates/secrets-engine'
const RULES = [
  'Engine = ' + ENG + ' (lib `envctl_secrets`). PURE RUST, stable, MSRV 1.80, NEVER prints (emits SecretEvent). Normal deps must stay async-free (NO tokio in [dependencies]); only the `relay_swap` method + the `Upstream` seam are async (async-trait, already a dep). Deps present: chacha20poly1305 0.10, argon2 0.5, hkdf 0.12, sha2 0.10, blake3 1.5, zeroize 1.8, subtle 2.6, rand 0.8, getrandom 0.2, serde, serde_json, toml, anyhow, thiserror, chrono, async-trait. MACs = blake3::keyed_hash; ct-compare = subtle. To test the async relay_swap you MAY add ONE dev-dependency to the engine crate ([dev-dependencies] only) — prefer `futures-executor = "0.3"` (pure Rust) + block_on; do NOT add a runtime to [dependencies].',
  'ALREADY DONE (reuse, do not rewrite): the functional vault (Engine init_vault/unlock/lock/secret_put/secret_get over keyslots+AEAD), vault/audit.rs hash chain, the expanded Store trait + real InMemStore (meta/secrets/keyslots/audit). broker/token.rs verify_bearer + mac_bearer. broker/policy.rs RelayPolicy/Bearer/RelayKind/SwapMode/Method/Provider/clamp_ttl/MAX_BEARER_TTL_SECS. broker/decide.rs has the RelayDecision/DenyReason/VerifiedBearer/CanonRequest TYPES + a todo!() decide(). broker/mod.rs has SwapOutcome + a unit `Broker` struct. lib.rs Engine has todo!() relay_mint/relay_revoke/relay_revoke_bearer/relay_swap + EgressReq/EgressResp.',
  'PRESERVE public method names + semantics. Refused ops are Ok-with-a-GuardRefused-event + Refused audit row, NOT Err. Every security op appends a DURABLE audit row BEFORE returning (HF-14) and emits a SecretEvent. The REAL secret/key is fetched ONLY inside an Allow decision and goes ONLY to Upstream.send — it is NEVER put in a SecretEvent, an audit row, an Err, or a returned value (CF-9 default-deny). A bearer is stored HASHED (mac only); the raw bearer never persists.',
].join('\n')

const DESIGN_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    bearer_format: { type: 'string', description: 'the raw wire bearer string layout enabling O(1) token_id lookup + constant-time MAC verify (e.g. `evrelay_<token_id>_<secret>`); how token_id + the MAC are derived; how the broker hmac_key is derived from the DEK (blake3 derive_key, domain-separated) and that it dies on lock.' },
    broker_state: { type: 'string', description: 'the Broker struct fields (policies cache? hmac_key derivation on unlock) + how relay policies persist via the Store (save/load/list_relay_policy) + how named vs ephemeral policies are created.' },
    decide_truth_table: { type: 'string', description: 'the EXACT default-deny order of checks in decide() mapping to each DenyReason (UnknownBearer/Disabled/Revoked/BearerRevoked/BearerExpired/PolicyExpired/HostNotAllowed/PathNotAllowed/MethodNotAllowed/UpstreamNotAllowed/PeerMismatch/SniHostMismatch/Budget*/RateLimited/GateAbsent/ClockRollback). Allow only if ALL pass. canonical_upstreams() per provider.' },
    mint_swap_flow: { type: 'string', description: 'relay_mint (USB-gate check, clamp_ttl<=24h, mint random raw via OsRng, store BearerRow{mac,...}, persist policy, audit RelayMinted w/o bearer) and the async relay_swap (parse token_id, load_bearer, verify_bearer ct, build VerifiedBearer+CanonRequest, decide(), on Allow fetch the real secret bytes from the unlocked vault and call Upstream.send + audit RelaySwapped allowed; on Deny audit + return Denied(reason); any internal error => InternalRefused, never send). relay_revoke / relay_revoke_bearer (fail-closed counts).' },
    test_plan: { type: 'string', description: 'tests: decide() hits EVERY DenyReason + the Allow path; relay_mint clamps a 1y request to <=24h and refuses when the USB gate is absent; relay_swap Allow path reaches a fake Upstream with the REAL key (assert the fake received the real secret, the caller got Allowed, and the real key never appears in any emitted SecretEvent); Deny path never calls the fake; a forged/expired/revoked bearer is denied. Use fake Clock/UsbProbe/Upstream + futures-executor block_on for the async test.' },
  },
  required: ['bearer_format', 'broker_state', 'decide_truth_table', 'mint_swap_flow', 'test_plan'],
}

const FIND = {
  type: 'object', additionalProperties: false,
  properties: { lens: { type: 'string' }, findings: { type: 'array', items: { type: 'object', additionalProperties: false, properties: {
    severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low'] }, issue: { type: 'string' }, fix: { type: 'string' }, confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
  }, required: ['severity', 'issue', 'fix', 'confidence'] } } },
  required: ['lens', 'findings'],
}

phase('Design')
log('Designing the broker contracts (bearer format, decide truth table, swap flow)...')
const design = await agent(
  'Design the env-ctl credential broker (Phase 4 core). Read the current ' + ENG + '/src/broker/*, lib.rs (Engine relay_* + EgressReq/Resp), vault/store.rs (Store relay methods), keyslot.rs, vault/audit.rs so your contracts fit the EXISTING types. Produce the contracts per schema — exact, buildable, reusing clamp_ttl/verify_bearer/mac_bearer and the functional vault. This is the virtual-credit-card core: the real key NEVER leaves the daemon; clients hold only a <=24h, scoped, revocable relay bearer.\n\n' + RULES,
  { label: 'design', phase: 'Design', schema: DESIGN_SCHEMA })

phase('Implement')
log('Implementing the broker end-to-end (single implementer for the interdependent core)...')
const impl = await agent(
  'Implement the env-ctl broker per the DESIGN below as ONE coherent change (Read each file first, then Write):\n' +
  '- ' + ENG + '/src/broker/decide.rs (implement decide() — pure, default-deny, every DenyReason)\n' +
  '- ' + ENG + '/src/broker/policy.rs (implement canonical_upstreams())\n' +
  '- ' + ENG + '/src/broker/mod.rs (Broker struct: hmac_key derivation from DEK + policy cache as needed)\n' +
  '- ' + ENG + '/src/lib.rs (implement Engine::relay_mint / relay_revoke / relay_revoke_bearer / relay_swap)\n' +
  '- ' + ENG + '/src/vault/store.rs (make InMemStore relay methods REAL: save/load/list_relay_policy, save/load_bearer, revoke_bearers_for_relay)\n' +
  'Add tests as ' + ENG + '/tests/relay.rs (use fake Clock/UsbProbe/Upstream; futures-executor dev-dep + block_on for the async swap). Keep ALL existing tests passing (lib unit + tests/phase0.rs + tests/vault.rs). Engine [dependencies] stay async-free; only relay_swap is async.\n\nDESIGN (JSON):\n' + JSON.stringify(design) + '\n\n' + RULES,
  { label: 'implement', phase: 'Implement' })

phase('Review')
log('3 adversarial reviewers attacking the broker...')
const LENSES = [
  'decide() + bearer forgery/replay: can a forged, expired, revoked, or wrong-peer bearer ever reach Allow? Is the check order truly default-deny (Allow ONLY if every clause passes)? Is verify_bearer constant-time and is the token_id lookup safe? Does the 24h expiry + clock-rollback (boottime floor) hold? Any DenyReason unreachable or any gap?',
  'relay_swap key-exposure (the load-bearing invariant): is the REAL secret/key fetched ONLY inside Allow, sent ONLY to Upstream.send, and NEVER placed in a SecretEvent, audit row, Err, log line, or return value? On ANY internal error does it become InternalRefused (a 403) rather than calling send()? Is the upstream host re-checked against canonical_upstreams() before send (HF-11)?',
  'relay_mint + USB-gating + persistence + COMPILE: is issuance refused fail-closed when the USB gate is absent? Is clamp_ttl applied so no bearer exceeds 24h or its policy? Is only the MAC persisted (never the raw bearer)? Are relay policies persisted/loaded correctly via the Store? Will it compile on pinned versions, do all existing + new tests pass, and do the engine [dependencies] stay async-free (executor only in [dev-dependencies])?',
]
const reviews = (await parallel(LENSES.map((lens, i) => () =>
  agent('Adversarially review the env-ctl broker through ONE lens:\n' + lens + '\nRead the implemented files under ' + ENG + '/src/broker/, lib.rs, vault/store.rs + ' + ENG + '/tests/relay.rs. Concrete flaws + concrete fixes; default to reporting when uncertain.\n\nIMPLEMENT NOTES:\n' + impl,
    { label: 'review:' + i, phase: 'Review', schema: FIND })
))).filter(Boolean)

phase('Fix')
log('Folding confirmed fixes...')
const fixed = await agent(
  'Finalize the env-ctl broker: read the files + review findings below, APPLY all confirmed critical/high/medium fixes (Edit/Write), and ensure the engine compiles on stable with pinned deps and ALL tests pass (lib unit + tests/phase0.rs + tests/vault.rs + tests/relay.rs). Preserve public method names. The real key must never escape an Allow swap. MACs=blake3::keyed_hash, ct-compare=subtle, engine [dependencies] async-free (executor only in [dev-dependencies]).\nFiles: ' + ENG + '/src/broker/{decide.rs,policy.rs,mod.rs}, ' + ENG + '/src/lib.rs, ' + ENG + '/src/vault/store.rs, ' + ENG + '/tests/relay.rs.\n\nFINDINGS (JSON):\n' + JSON.stringify(reviews) + '\n\n' + RULES,
  { label: 'fix', phase: 'Fix' })

log('Phase-4 broker implemented + reviewed + fixed.')
return { design, impl, reviews, fixed }