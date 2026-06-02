export const meta = {
  name: 'env-ctl-server-mode',
  description: 'Design + adversarially review the env-ctl server-mode delta (central daemon, remote relay-only clients, libSQL) and write SERVER-MODE.md',
  phases: [
    { title: 'Delta', detail: '3 architects: store/server, remote-relay, threat/deployment' },
    { title: 'Harden', detail: '3 adversarial reviewers on the network/remote/VPS surface' },
    { title: 'Write', detail: 'fold fixes, write SERVER-MODE.md + return targeted doc edits' },
  ],
}

const REPO = '/home/drdave/Desktop/env-ctl'

const BRIEF = [
  'env-ctl SERVER-MODE delta. The full prior design lives in ' + REPO + '/docs/ (READ ARCHITECTURE.md, DESIGN-NOTES.md, THREAT-MODEL.md, ROADMAP.md, SCAFFOLD-SPEC.md, db/schema.sql). The original 12 operator decisions + 62-finding adversarial pass STAND. These NEW operator rulings refine three of them; design the delta, do not rewrite the whole system:',
  'NEW-1 TOPOLOGY: ONE central `secretd` owns the libSQL vault (on THIS dual-5090 box OR a VPS). Remote THIN clients (a Telegram-hosted cloud agent, phone, laptop) connect IN. Single source of truth. (Refines decision #2 single-box -> central server + remote relay clients.)',
  'NEW-2 REMOTE AUTH: remote clients get RELAY-BEARERS ONLY over HTTPS. They may USE brokered credentials (<=24h scoped relay) but CANNOT reach the control plane. The CONTROL plane stays LOCAL UDS + SO_PEERCRED (owner-only vault management on the daemon host). NO remote vault management, ever. (Refines decision #8: control stays local UDS; ADD a remote relay HTTPS data plane.)',
  'NEW-3 OI-1 RESOLVED = libSQL. Its server/replica/sync is the required feature (a pure-Rust local-only store like redb cannot serve remote clients). The bundled C SQLite is an ACCEPTED, SCOPED waiver: the `envctl-secrets-engine` LIB stays pure-Rust (portable/mergeable); libSQL + its C core live ONLY in the store/daemon layer. Prefer a deployment that isolates the C core (embedded libSQL on the daemon host, or a remote-HTTP libSQL client to a separate sqld). (Refines decisions #1/#3.)',
  'CONSEQUENCES you MUST resolve (the original design did not anticipate remote clients):',
  'C-A REMOTE BEARER BINDING: bearers were peer-bound to the local caller uid/pid via SO_PEERCRED (finding HF-8). Remote cloud agents have NO local uid/pid. Design a remote binding that preserves the guarantees: bind to a client identity (per-client relay credential / client certificate / registered client-id) + sensible source constraints; keep <=24h rotation, scope, USB-gated issuance, and per-client revocation + audit traceability.',
  'C-B USB-GATING vs TOPOLOGY: USB-presence gating assumes the USB is on the daemon host. If `secretd` runs on a VPS the USB cannot be there. Resolve FAIL-CLOSED (no silent downgrade): either (a) daemon runs on THIS box (USB local) and ONLY the relay HTTPS endpoint is exposed to the network; or (b) define a concrete VPS gating story (e.g. the operator box holds the USB and authorizes issuance; or VPS mode explicitly substitutes another hardware/operator factor). Recommend one as default and document the tradeoff.',
  'C-C REMOTE RELAY ENDPOINT = new network attack surface: TLS cert strategy for the public relay endpoint (remote clients/Telegram must trust it -> a PUBLICLY-TRUSTED cert, NOT the local MITM CA which is only for intercepting upstreams); rate-limit/DoS; ensure the control plane is PROVABLY unreachable over the network; libSQL C-core now in a network-facing daemon; if VPS, secrets-at-rest live off the operator box (app-encrypted) — state the posture.',
  'Keep envctl discipline throughout: fail-closed, dry-run-by-default for destructive ops, never touch user data, refuse on ambiguity, the engine never prints (SecretEvent stream).',
].join('\n')

const DIM_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    dimension: { type: 'string' },
    overview: { type: 'string' },
    key_decisions: { type: 'array', items: { type: 'object', additionalProperties: false, properties: { decision: { type: 'string' }, rationale: { type: 'string' } }, required: ['decision', 'rationale'] } },
    artifacts: { type: 'string', description: 'Concrete: Rust/trait sigs, libSQL wiring, bearer-binding scheme, TLS/cert plan, threat rows, deployment steps, schema deltas.' },
    consequences_resolved: { type: 'array', items: { type: 'string' }, description: 'How C-A / C-B / C-C are resolved (if this dimension touches them).' },
    risks: { type: 'array', items: { type: 'string' } },
  },
  required: ['dimension', 'overview', 'key_decisions', 'artifacts'],
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

const DIMS = [
  { key: 'store-server', prompt: 'Design the libSQL CENTRAL store for the daemon. Cover: embedded libSQL on the daemon host vs a separate sqld with a remote-HTTP client (and which keeps the C core most isolated / keeps the engine lib pure-Rust); the concrete `Store` trait impl over libSQL expressing db/schema.sql; that app-layer XChaCha20-Poly1305 encryption is UNCHANGED (libSQL only ever sees ciphertext + non-secret metadata); the audit-log hash-chain on libSQL; backup + migration from the Phase-0 inmem store; the CI no-C gate now EXEMPTS the store/daemon layer but still forbids C in the engine lib (cargo tree -p envctl-secrets-engine must stay C-free). Give the Cargo wiring (which crate gets the libsql dep + feature flag) and the schema.sql header update.' },
  { key: 'remote-relay', prompt: 'Design the REMOTE relay data plane. The relay proxy is exposed over HTTPS so remote clients (Telegram cloud agent, phone, laptop) present a relay bearer and get credentialed egress; the control plane stays LOCAL UDS only (prove it is never bound to a network interface). RESOLVE C-A: a remote bearer-binding scheme to replace SO_PEERCRED uid/pid binding — bind to a client identity (registered client-id / client certificate / mTLS identity) + source constraints, preserving <=24h rotation, scope, USB-gated issuance, per-client revocation, and per-client audit. RESOLVE C-C TLS: the public relay endpoint needs a PUBLICLY-TRUSTED cert (not the local MITM CA); specify how (e.g. a real cert / pinned cert / reverse proxy) and rate-limit/DoS protections. Give the concrete Telegram-cloud-agent flow end to end (register client -> mint bound bearer -> agent calls relay over HTTPS -> swap -> upstream), and Rust trait/type deltas (e.g. a ClientIdentity + a network Transport alongside the UDS one).' },
  { key: 'threat-deployment', prompt: 'Produce the THREAT-MODEL delta + DEPLOYMENT guidance. New adversaries: network attacker against the relay HTTPS endpoint; a compromised remote/Telegram agent holding a bearer; a compromised VPS; theft/replay of a remote bearer. RESOLVE C-B fail-closed: pick a DEFAULT (recommend: daemon on THIS box with the USB local, exposing ONLY the relay HTTPS endpoint; control plane never leaves the box) and document the VPS alternative + its tradeoff (USB cannot be on a VPS -> either operator-box-authorizes-issuance, or an explicit substitute factor; NEVER a silent downgrade). Add updated INVARIANTS / FORBIDDEN STATES: control plane is never network-reachable; remote clients never receive control RPCs; a remote bearer is never valid >24h and never issued while the gate is absent; the public relay cert is never the MITM CA; if VPS, secrets-at-rest are off-box but always app-encrypted. Give a this-box-vs-VPS decision table + concrete deployment steps for the recommended default.' },
]

phase('Delta')
log('3 architects designing the server-mode delta (central daemon + remote relay-only clients + libSQL)...')
const designs = (await parallel(DIMS.map(d => () =>
  agent(BRIEF + '\n\nYOUR DIMENSION: ' + d.key + '\n\nProduce the delta for this dimension. Read the existing docs in ' + REPO + '/docs/ first for consistency.',
    { label: 'delta:' + d.key, phase: 'Delta', schema: DIM_SCHEMA })
))).filter(Boolean)

phase('Harden')
log('3 adversarial reviewers attacking the network/remote/VPS surface...')
const LENSES = [
  'remote bearer binding + relay-over-network: can a stolen/replayed bearer be used by an attacker who is NOT the bound client? Does the binding actually hold without SO_PEERCRED? Are <=24h rotation + scope + revoke + audit traceability preserved for remote clients? Any way a remote client escalates to control-plane access?',
  'USB-gating integrity across topology: does USB-presence gating still mean something in the chosen default? Is there ANY silent downgrade when the USB is absent or when on a VPS? Is issuance truly refused fail-closed without the gate? Does the VPS story introduce a bypass?',
  'attack surface + control-plane isolation + data-at-rest: is the control plane PROVABLY unreachable over the network (not merely "we did not document a network bind")? Public relay endpoint hardening (TLS, rate-limit, DoS, auth before swap). libSQL C core now in a network-facing daemon — memory-safety/exposure. If VPS, what is the real posture of off-box (app-encrypted) secrets + the libSQL data?',
]
const findings = (await parallel(LENSES.map((lens, i) => () =>
  agent('Adversarially review the env-ctl server-mode delta through ONE lens:\n' + lens + '\nBe a skeptic; give concrete flaws + concrete fixes. Default to reporting when uncertain.\n\n' + BRIEF + '\n\nDELTA DESIGNS (JSON):\n' + JSON.stringify(designs),
    { label: 'harden:' + i, phase: 'Harden', schema: FINDINGS_SCHEMA })
))).filter(Boolean)

const total = findings.reduce((n, f) => n + (f.findings ? f.findings.length : 0), 0)
log('Folding ' + total + ' findings, writing SERVER-MODE.md + computing doc edits...')
const out = await agent(
  'You are the lead architect finalizing the env-ctl SERVER-MODE delta. Fold CONFIRMED critical/high findings into the design; record medium/low as OPEN ITEMS. Then:\n' +
  '1. WRITE ' + REPO + '/docs/SERVER-MODE.md (self-contained): the resolved rulings (NEW-1/2/3), the central-daemon + remote-relay-only architecture, the libSQL central store + C-isolation, the RESOLVED remote bearer-binding scheme (C-A), the RESOLVED USB-gating-vs-topology default + VPS tradeoff (C-B), the public relay endpoint TLS + hardening (C-C), a this-box-vs-VPS decision table + deployment steps, and a THREAT-MODEL DELTA (new adversaries + new invariants/forbidden-states). Match envctl doc style.\n' +
  '2. RETURN a JSON object: {summary, server_mode_md_written:bool, critical_fixes:[strings], doc_edits:[{file, find_snippet, replace_with, why}]} where doc_edits are PRECISE, minimal one-spot edits I will apply by hand to reconcile the already-committed docs that now contradict these rulings — specifically: db/schema.sql header (says backend OPEN / recommends redb -> now libSQL resolved, C-isolated), Cargo.toml workspace comment (says "no libsql row" -> libSQL lands Phase 1 in store/daemon, C-isolated), crates/secrets-engine/src/vault/store.rs note, docs/DESIGN-NOTES.md OI-1 entry (-> RESOLVED: libSQL), and docs/ROADMAP.md (note libSQL backend + a remote-relay-HTTPS phase). Keep find_snippet short + exact-ish so I can locate it.\n\n' +
  BRIEF + '\n\nDELTA DESIGNS (JSON):\n' + JSON.stringify(designs) + '\n\nFINDINGS (JSON):\n' + JSON.stringify(findings),
  { label: 'write+edits', phase: 'Write' })

log('SERVER-MODE.md written; doc-edit list returned.')
return out