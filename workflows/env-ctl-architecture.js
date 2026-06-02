export const meta = {
  name: 'env-ctl-architecture',
  description: 'Design + adversarially harden the env-ctl secrets-broker architecture and write its design docs',
  phases: [
    { title: 'Design', detail: '7 parallel architects, one per subsystem dimension' },
    { title: 'Synthesize', detail: 'lead architect reconciles dimensions into one coherent architecture' },
    { title: 'Harden', detail: '6 adversarial security reviewers, then fold fixes + write docs to disk' },
  ],
}

const REPO = '/home/drdave/Desktop/env-ctl'
const ENVCTL = '/home/drdave/Desktop/envctl'

const LOCKED = [
  'env-ctl LOCKED OPERATOR DECISIONS (do not relitigate; design to these):',
  '1. Pure-Rust Cargo workspace, STABLE toolchain, edition 2021, rust-version 1.80, license MIT OR Apache-2.0. Few mainstream deps. NO web UI / NO WebView. Mirrors envctl conventions and WILL MERGE into envctl/crates/. The engine is a pure LIBRARY that NEVER prints — it emits a structured Event stream; the CLI/daemon are thin front-ends (exactly like envctl-engine).',
  '2. Mission: a local, single-operator secrets VAULT + credential BROKER for one Ubuntu 26.04 dual-RTX-5090 box. Fills envctl Non-Goal N6 (envctl explicitly is NOT a secrets manager).',
  '3. Storage/crypto: libSQL/SQLite store with APP-LAYER encryption — XChaCha20-Poly1305 AEAD per record, key via argon2id. Ciphertext + metadata/version/audit tables in the DB. NO SQLCipher, NO C deps.',
  '4. Unlock (USB-skips-passphrase 2FA): a USB key device identified by its PARTITION UUID holds a high-entropy keyfile. USB present => auto-unlock (no prompt). USB absent => argon2id PASSPHRASE FALLBACK. A single vault must be openable by EITHER factor (LUKS-style keyslots: the data-encryption key is wrapped under both a USB-keyfile KEK and a passphrase KEK). Keys are zeroized in RAM; the unlock key is never written to disk.',
  '5. Credential broker = the inject model (think VIRTUAL CREDIT CARDS): the real long-lived key NEVER leaves the daemon. The broker issues per-client RELAY tokens and SWAPS them for the real key at egress. Data-plane modes: (a) base-URL repoint where the client supports a custom API base (e.g. Claude honors ANTHROPIC_BASE_URL); (b) HTTPS_PROXY + local-CA MITM for hardcoded-host clients (git/gh); (c) OPTIONAL native scoped sub-token mint where the provider supports it (GitHub fine-grained PAT / App installation token, OpenAI project keys). Each relay carries a POLICY: real-key mapping, host/path + method allowlist, expiry, rate/quota budget, enabled/revoked. Full per-client audit.',
  '6. Relay rotation + USB gating: every relay BEARER token rotates/expires within 24 HOURS, and issuance/renewal is GATED ON USB PRESENCE — pull the USB and relay keys time out (<=24h) and are not renewed. 24h rotation limits blast radius and gives TRACEABILITY (any abuse maps to a client + 24h window). A NAMED relay (e.g. claude-main 1yr, gh-ci 90d) is a long-lived POLICY; the wire bearer minted under it is always <=24h. EPHEMERAL relay = a one-off minted by env-ctl run for a single process, also <=24h.',
  '7. Relay identity model: support BOTH named long-lived relay policies AND ephemeral per-invocation tokens.',
  '8. API: gRPC over a Unix-domain socket for the CONTROL plane; authz by SO_PEERCRED (uid). The relay proxy is the DATA plane (HTTP/HTTPS).',
  '9. Auto-inject: env-ctl run -- <cmd> exec-wrapper injects the relay token + base-URL/proxy env into the CHILD ONLY; the real key never enters the child env, shell history, or git. Optional per-directory profiles.',
  '10. Certs pillar: a LOCAL CA (issue/renew/revoke leaf certs) powers the MITM data-plane TLS and optional control-plane mTLS; trust-store wiring per tool (NODE_EXTRA_CA_CERTS, REQUESTS_CA_BUNDLE, GIT_SSL_CAINFO, CURL_CA_BUNDLE, SSL_CERT_FILE) and/or the system bundle, under envctl reversible Wiring discipline.',
  '11. Safety: inherit the envctl boot-repair gold standard — fail-closed guards, dry-run by default for destructive ops, back up before clobber, never touch user data, refuse on ambiguity. Define forbidden states.',
  '12. XDG layout, env-ctl-namespaced: ~/.config/env-ctl, ~/.local/share/env-ctl (0700), ~/.local/state/env-ctl (logs), runtime socket under XDG_RUNTIME_DIR. Crate/package names MUST NOT collide with envctl-engine / envctl / envctl-gui on merge.',
].join('\n')

const CONVENTIONS = 'envctl conventions to MATCH (you MAY read ' + ENVCTL + ' read-only; key files: crates/engine/src/lib.rs, component.rs, model.rs, docs/PRD.md, docs/ARCHITECTURE.md): one engine lib (no printing/clap/egui), Event stream over mpsc, a single behavioral-seam trait for testing (like HookRunner), typed EngineError for setup-time failures only, best-effort runs ending in a summary, XDG paths. The env-ctl repo is at ' + REPO + ' and already contains README.md + docs/CHARTER.md (read them).'

const DIM_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    dimension: { type: 'string' },
    overview: { type: 'string' },
    key_decisions: { type: 'array', items: { type: 'object', additionalProperties: false, properties: { decision: { type: 'string' }, rationale: { type: 'string' } }, required: ['decision', 'rationale'] } },
    artifacts: { type: 'string', description: 'Concrete buildable artifacts for THIS dimension: Rust type/trait signatures, SQL DDL, .proto, CLI verbs, file skeletons — whatever applies.' },
    dependencies: { type: 'array', items: { type: 'string' }, description: 'Real crate names (+ rough versions) this dimension needs; flag any that strain the few-deps/stable/no-web tenet.' },
    risks: { type: 'array', items: { type: 'string' } },
    merge_into_envctl: { type: 'string' },
  },
  required: ['dimension', 'overview', 'key_decisions', 'artifacts', 'dependencies'],
}

const SYNTH_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    architecture_md: { type: 'string' },
    design_notes_md: { type: 'string' },
    roadmap_md: { type: 'string' },
    threat_model_md: { type: 'string' },
    scaffold_spec_md: { type: 'string', description: 'Crate layout + each crate Cargo.toml + lib.rs module list + key type signatures + build notes — precise enough to hand-write a COMPILING Phase-0 scaffold.' },
    control_plane_proto: { type: 'string' },
    libsql_schema_sql: { type: 'string' },
    workspace_cargo_toml: { type: 'string' },
    crate_layout: { type: 'array', items: { type: 'object', additionalProperties: false, properties: { path: { type: 'string' }, package: { type: 'string' }, kind: { type: 'string' }, purpose: { type: 'string' }, deps: { type: 'array', items: { type: 'string' } } }, required: ['path', 'package', 'kind', 'purpose'] } },
  },
  required: ['architecture_md', 'design_notes_md', 'roadmap_md', 'threat_model_md', 'scaffold_spec_md', 'control_plane_proto', 'libsql_schema_sql', 'workspace_cargo_toml', 'crate_layout'],
}

const FINDINGS_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    lens: { type: 'string' },
    findings: { type: 'array', items: { type: 'object', additionalProperties: false, properties: {
      severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low'] },
      issue: { type: 'string' },
      fix: { type: 'string' },
      confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
    }, required: ['severity', 'issue', 'fix', 'confidence'] } },
  },
  required: ['lens', 'findings'],
}

const DIMENSIONS = [
  { key: 'workspace-engine', prompt: 'Design the Cargo workspace + crate layout + the shared ENGINE LIBRARY API. Choose package/lib names that DROP INTO envctl/crates/ with NO collision (envctl-engine/envctl/envctl-gui exist) — e.g. a secrets-engine lib, a broker/proxy crate, the daemon bin, the CLI bin. For EACH crate give: path, package name, lib-or-bin, responsibility, and a REAL dependency set (libsql, tokio, tonic+prost+prost-build, chacha20poly1305, argon2, hkdf, zeroize, rand, rcgen, rustls + rustls-pemfile, hyper or reqwest, serde, thiserror, anyhow, clap, tracing, etc.). Justify the async runtime (tokio for gRPC + the proxy) and the MINIMAL HTTP stack for the relay proxy without violating no-web/no-WebView. Define the core Event enum (engine-never-prints spine) and the top-level handle, mirroring envctl-engine/src/lib.rs. Define cargo FEATURE flags. Give an explicit MERGE-INTO-ENVCTL plan (how these crates + the shared [workspace.dependencies] unify; how secrets CLI verbs fold into the envctl binary).' },
  { key: 'data-model-crypto', prompt: 'Design the libSQL/SQLite schema and the APP-LAYER encryption-at-rest envelope. Tables at least: secrets, secret_versions, relay_policies, relay_bearers (store only HASHED bearer tokens), audit_log (hash-chained / tamper-evident), keyslots (LUKS-style: DEK wrapped under USB-keyfile KEK and passphrase KEK), ca_store/certs. Define the KEY HIERARCHY (unlock factor -> KEK -> wrapped DEK -> per-record XChaCha20-Poly1305 with unique nonce + AAD binding record identity). Specify argon2id params (memory/time/lanes) suitable for an interactive unlock on a high-end box. Cover DEK rotation + re-encryption, secret version history, and audit-log tamper-evidence. Give the SQL DDL and the Rust record/serialization types.' },
  { key: 'keymgmt-unlock', prompt: 'Design the unlock/keymgmt state machine for the USB-skips-passphrase 2FA model. USB device identified by PARTITION UUID holding a high-entropy keyfile => auto-unlock; USB absent => argon2id passphrase fallback. Show the keyslot design so ONE vault opens via EITHER factor (DEK wrapped under both a USB-keyfile-derived KEK and a passphrase-derived KEK). Design the 24-HOUR relay-rotation clock and the USB-PRESENCE GATING of relay issuance: how presence is detected by partition UUID (poll vs udev), what counts as present, and what happens to live AND future relay bearers when the USB is pulled (must time out <=24h, no renewal). Specify zeroization (zeroize crate), lock-on-demand, never-key-to-disk, and the traceability hooks (which events fire for unlock/lock/USB-insert/remove/relay-mint). Define the Lock/Unlock state enum + transitions.' },
  { key: 'broker-relay', prompt: 'Design the credential-broker DATA PLANE (virtual-credit-card model). Relay BEARER token format (random, prefixed, e.g. relay_<provider>_<rand>), stored HASHED, constant-time verify. Per-relay POLICY: real-key mapping, host/path allowlist, method allowlist, expiry <=24h, rate/quota budget, enabled/revoked. The SWAP at egress in 3 modes: (a) base-URL repoint (client -> local plain-HTTP endpoint authed by relay token -> broker swaps to the real key -> re-originates TLS to the REAL upstream, verifying the upstream cert); (b) HTTPS_PROXY CONNECT + local-CA MITM for hardcoded-host clients; (c) OPTIONAL native scoped sub-token mint for GitHub (fine-grained PAT / App installation token) and OpenAI project keys. Define a per-provider Adapter trait (anthropic, github, openai, generic) covering auth-header rewrite, streaming/SSE pass-through (Anthropic streaming!), and allowlist enforcement. Cover 24h bearer rotation under named policies + ephemeral, USB-gated issuance, and per-request audit fields. Give Rust trait + type signatures.' },
  { key: 'certs-ca', prompt: 'Design the LOCAL CA + leaf-cert subsystem (rcgen-based). CA keypair generation + storage (CA private key ENCRYPTED in the vault, never on disk in clear). On-the-fly leaf minting per intercepted upstream SNI with an in-memory cache, for the MITM proxy; optional leaf certs for control-plane mTLS. Renew/revoke (short TTL preferred over CRL). Trust-store WIRING so clients trust our CA, per tool (NODE_EXTRA_CA_CERTS, REQUESTS_CA_BUNDLE, GIT_SSL_CAINFO, CURL_CA_BUNDLE, SSL_CERT_FILE) and/or the system bundle (update-ca-certificates) under envctl reversible-Wiring discipline (guarded blocks, backup-before-clobber, clean revert). Enumerate the SECURITY PITFALLS of a private MITM CA on the box and how to bound them (leaf certs ONLY for hosts we are actively intercepting for a valid relay; CA key access requires an unlocked vault; never install the CA where it could intercept non-brokered traffic silently). Give Rust signatures.' },
  { key: 'api-cli-inject', prompt: 'Design the gRPC CONTROL plane (.proto) and the CLI/inject surface. Proto services: Vault (add/get/list/rm/rotate secrets), Relay (create/revoke/list policies + mint bearer), Certs (CA + leaf ops + trust-wiring), Lock (unlock/lock/status), Audit (query). UDS transport + SO_PEERCRED uid authz (reject non-owner uids). Define the env-ctl CLI verbs and ESPECIALLY env-ctl run -- <cmd>: the per-provider env mapping (Anthropic: ANTHROPIC_BASE_URL + ANTHROPIC_API_KEY=relay; GitHub: GH_TOKEN=relay + HTTPS_PROXY + CA env; OpenAI: OPENAI_BASE_URL + OPENAI_API_KEY=relay; generic: HTTPS_PROXY + CA env), plus optional per-directory profiles (e.g. a .env-ctl file selecting which relays). Mirror envctl CLI ergonomics: --json output, dry-run-by-default for destructive verbs, the engine emits Events and the CLI drains+prints (engine never prints). Give the full .proto and the clap command tree.' },
  { key: 'threat-model-roadmap', prompt: 'Produce a STRIDE-style THREAT MODEL for env-ctl. Adversaries: a local non-owner process/uid; malware running inside the operators own session; accidental git commit of secrets; a stolen disk/backup; a stolen USB key; network MITM of the brokers REAL upstream calls; a compromised client that holds a relay token. For each, the mitigation grounded in the locked decisions. Define fail-closed INVARIANTS and FORBIDDEN STATES mirroring envctl REQ-SAFE-*/FS-* — at minimum: a real key must NEVER appear in a child process env; the vault is NEVER written unencrypted; a relay bearer is NEVER valid >24h; USB-absent must NEVER silently grant long-lived relay access; a CA leaf is ONLY minted for a host being actively intercepted for a valid relay; destructive verbs are dry-run by default; user data is never touched. Then produce a PHASED ROADMAP in envctl style: Phase 0 scaffold-that-compiles -> vault core (libSQL + AEAD + keyslots) -> keymgmt/unlock (USB UUID + passphrase fallback + zeroize) -> broker/relay (24h rotation + USB gating + adapters) -> certs/CA + MITM -> gRPC daemon (UDS + peercred) -> inject/run -> envctl MERGE. Each phase: scope + acceptance criteria.' },
]

phase('Design')
log('Fanning out 7 architects across the env-ctl subsystems...')
const designs = (await parallel(DIMENSIONS.map(d => () =>
  agent(LOCKED + '\n\n' + CONVENTIONS + '\n\nYOUR DIMENSION: ' + d.key + '\n\n' + d.prompt,
    { label: 'design:' + d.key, phase: 'Design', schema: DIM_SCHEMA })
))).filter(Boolean)

phase('Synthesize')
log('Reconciling ' + designs.length + ' dimension designs into one architecture...')
const synth = await agent(
  'You are the LEAD ARCHITECT for env-ctl. Reconcile the dimension designs below into ONE coherent, BUILDABLE architecture, resolving cross-cutting conflicts (data-model<->keymgmt keyslots; broker<->certs MITM; api<->broker planes; 24h rotation across named/ephemeral relays; engine-never-prints Event spine across all crates). Produce ALL artifacts per the schema. The crate_layout MUST drop into envctl/crates/ with NO name collision (envctl-engine/envctl/envctl-gui exist). Keep deps minimal + stable; honor no-web/no-WebView (a local HTTP relay proxy + a gRPC control plane are allowed — pick the minimal stack and justify it). Write docs in envctl doc style (status header, tables, REQ-style numbering where apt). The scaffold_spec_md must be precise enough that a careful engineer can hand-write a COMPILING Phase-0 scaffold (workspace + crate stubs + module lists + key type signatures, with todo!()/unimplemented behavior).\n\n' + LOCKED + '\n\n' + CONVENTIONS + '\n\nDIMENSION DESIGNS (JSON):\n' + JSON.stringify(designs),
  { label: 'synthesize', phase: 'Synthesize', schema: SYNTH_SCHEMA })

phase('Harden')
log('6 adversarial reviewers attacking the design...')
const LENSES = [
  'crypto-at-rest correctness: AEAD usage, nonce uniqueness & length (XChaCha20-Poly1305 24-byte nonce), AAD binding to record identity, argon2id params, the DEK/KEK keyslot soundness, and safe re-encryption on DEK rotation.',
  'key handling in RAM: zeroization coverage, never-key-to-disk, USB-keyfile read/handling, USB-presence-gating BYPASS paths, and passphrase-fallback DOWNGRADE attacks (can an attacker force the weaker factor?).',
  'relay token security: bearer forgery, replay, hashed-at-rest + constant-time verify, the 24h rotation soundness, named-policy vs ephemeral correctness, the invariant that USB-absent must NOT grant long-lived access, and whether the audit trail truly gives per-client/per-window traceability.',
  'CA / MITM + egress trust: blast radius of a private MITM CA on the box, leaf scoping to ONLY actively-intercepted hosts, CA key protection (must require an unlocked vault), reversibility of trust-store wiring, and that TLS verification to the REAL upstream is still enforced after the swap.',
  'fail-closed + forbidden states vs envctl discipline: real key never in a child env, vault never written plaintext, relay never >24h, dry-run defaults, refuse-on-ambiguity, never touch user data — list every gap as a forbidden-state miss with a fix.',
  'merge-into-envctl + dependency hygiene: crate-name collisions with envctl-engine/envctl/envctl-gui, workspace dependency unification conflicts, stable-toolchain compliance, the few-deps/no-web tenet, and a green build with and without feature flags.',
]
const findings = (await parallel(LENSES.map((lens, i) => () =>
  agent('Adversarially review this env-ctl design through ONE lens:\n' + lens + '\nBe a skeptic — find concrete, specific flaws and give a concrete fix for each. Default to reporting an issue when uncertain. If the design is sound on this lens, say so with low-severity notes only.\n\n' + LOCKED + '\n\nDESIGN (JSON):\n' + JSON.stringify(synth),
    { label: 'harden:' + i, phase: 'Harden', schema: FINDINGS_SCHEMA })
))).filter(Boolean)

const totalFindings = findings.reduce((n, f) => n + (f.findings ? f.findings.length : 0), 0)
log('Folding ' + totalFindings + ' review findings and writing docs to disk...')
const final = await agent(
  'You are the lead architect finalizing env-ctl. Fold the CONFIRMED review findings into the design: fix all critical/high issues directly in the artifacts; record medium/low items as explicit OPEN ITEMS in DESIGN-NOTES. Then WRITE the final artifacts to disk using the Write tool at EXACTLY these absolute paths (create directories as needed):\n' +
  '- ' + REPO + '/docs/ARCHITECTURE.md  (from architecture_md)\n' +
  '- ' + REPO + '/docs/DESIGN-NOTES.md  (from design_notes_md; include a RESOLVED DECISIONS table citing the locked operator choices, and a REVIEW FIXES section summarizing what the adversarial pass changed)\n' +
  '- ' + REPO + '/docs/ROADMAP.md  (from roadmap_md)\n' +
  '- ' + REPO + '/docs/THREAT-MODEL.md  (from threat_model_md)\n' +
  '- ' + REPO + '/docs/SCAFFOLD-SPEC.md  (from scaffold_spec_md; EMBED the final workspace Cargo.toml and each crate Cargo.toml verbatim in fenced blocks, plus per-crate lib.rs module lists and key type signatures — precise enough to hand-write a compiling Phase-0 scaffold)\n' +
  '- ' + REPO + '/docs/api/control-plane.proto  (from control_plane_proto)\n' +
  '- ' + REPO + '/docs/db/schema.sql  (from libsql_schema_sql)\n' +
  'After writing, RETURN a compact JSON object: {summary, files_written:[absolute paths], crate_layout:[{path,package,kind}], critical_fixes_applied:[strings]}.\n\n' +
  LOCKED + '\n\nSYNTHESIZED DESIGN (JSON):\n' + JSON.stringify(synth) + '\n\nADVERSARIAL REVIEW FINDINGS (JSON):\n' + JSON.stringify(findings),
  { label: 'finalize+write', phase: 'Harden' })

log('env-ctl architecture + design docs written under ' + REPO + '/docs/.')
return final