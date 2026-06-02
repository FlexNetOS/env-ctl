export const meta = {
  name: 'env-ctl-ops-research',
  description: 'Deployment + operations design fleet: systemd/sqld, envctl-component packaging, USB ceremony, backup/rotation, audit signing/monitoring, run UX, CI/supply-chain',
  phases: [
    { title: 'Research', detail: '7 topics researched (web + repo)' },
    { title: 'Write', detail: 'one ops design doc per topic under docs/ops/' },
  ],
}

const REPO = '/home/drdave/Desktop/env-ctl'
const CTX = 'env-ctl = pure-Rust local-+server secrets vault + credential broker (central secretd daemon owns a libSQL vault via sqld-on-loopback + pure-Rust remote client; relay-bearers-only over HTTPS for remote thin clients incl. a Telegram cloud agent; control plane = local UDS + SO_PEERCRED; on-box USB-PARTUUID unlock default, VPS deferred). It will MERGE into envctl (~/Desktop/envctl, a declarative TOML-component env manager with the 5 verbs). Design docs: ' + REPO + '/docs/ (ARCHITECTURE, SERVER-MODE, THREAT-MODEL, DESIGN-NOTES, ROADMAP, research/*). Produce a CONCRETE, sourced ops/deploy design for this exact system. Cite versions/URLs; flag UNVERIFIED. READ-ONLY (no code changes).'

const TOPICS = [
  { slug: 'systemd-hardening', title: 'secretd + sqld as hardened systemd services', q: 'systemd user (or system) units for secretd + a loopback-only sqld: socket activation for the UDS, dependency ordering, and the full hardening directive set (NoNewPrivileges, ProtectSystem=strict, ProtectHome, PrivateTmp, MemoryDenyWriteExecute, RestrictAddressFamilies=AF_UNIX+AF_INET, SystemCallFilter=@system-service, CapabilityBoundingSet, LockPersonality, ProtectKernel*, RestrictNamespaces). sqld bound to 127.0.0.1 with JWT(Ed25519) auth required. Tie to env-ctl mlockall/RLIMIT_CORE (research/05).' },
  { slug: 'envctl-component', title: 'Packaging env-ctl as an envctl manifest component', q: 'Read ~/Desktop/envctl (manifest/*.toml, docs/ARCHITECTURE.md, crates/engine component model: Component/Hook/Wiring/Guard). Design the TOML component(s) so `envctl install env-ctl` builds + installs secretd/secretctl/sqld, wires the systemd units + the env-ctl run shell integration, all reversibly (guarded blocks, backup-before-clobber). Detect/verify/fix/remove hooks. How the secrets components depend on rust/build deps.' },
  { slug: 'usb-ceremony', title: 'USB key ceremony, keyslot enrollment, recovery', q: 'Operator UX to: generate a 64-byte CSPRNG keyfile onto a USB, capture its GPT PARTUUID, enroll a USB keyslot + a passphrase keyslot (LUKS-style), and produce a recovery path if the USB is lost (a high-entropy recovery passphrase / printed recovery code as a 3rd keyslot). Concrete `env-ctl` verbs + safety prompts. How to make the keyfile not trivially copyable (it is — so what does the PARTUUID binding actually buy; document honestly per research/04).' },
  { slug: 'backup-rotation', title: 'Vault backup/restore + DEK & keyslot rotation runbook', q: 'What to back up (the libSQL data behind sqld = app-encrypted blobs + keyslots + audit chain; everything is ciphertext, so backups are safe off-box). Restore procedure. DEK rotation (O(all-secrets) re-encrypt, dek_generation bump, atomic/resumable) vs keyslot rotation (O(1)). When to rotate. Interaction with embedded-replica sync. Audit-chain continuity across backup/restore.' },
  { slug: 'audit-signing-monitoring', title: 'Ed25519 audit-head signing + log export/monitoring', q: 'Ed25519 (ed25519-dalek, RFC 8032) signing of the hash-chain head; rotate the signing key on USB unlock (forward security); publish the public key for off-box verification. Export the audit log (NDJSON) to a SIEM / journald; alerting rules (failed unlock, USB pull, relay swap to a new host, chain-verify failure). Optional RFC 3161 / OpenTimestamps anchoring (research/13).' },
  { slug: 'run-inject-ux', title: 'env-ctl run UX + .env-ctl profile format + injection table', q: 'The `env-ctl run [--relay ..] -- <cmd>` exec-wrapper UX; the per-directory `.env-ctl` profile file format (which relays, trusted-root rules, confirmation for named-relay attach per FS-S15); and the concrete per-provider injection env tables (Anthropic: ANTHROPIC_BASE_URL+ANTHROPIC_API_KEY=bearer; GitHub: GH_TOKEN=bearer + HTTPS_PROXY + CA env; OpenAI: OPENAI_BASE_URL+OPENAI_API_KEY; generic: HTTPS_PROXY+CA), referencing research/08/09/10/11.' },
  { slug: 'ci-supplychain', title: 'CI, MSRV, no-C gates, supply-chain', q: 'A CI design for env-ctl: per-crate no-C gate (`! cargo tree -p envctl-secrets-engine | grep -E libsql-ffi|sqlite3-sys|openssl-sys|aws-lc`), single-rustls + ring-not-aws-lc gates, MSRV 1.80 (`cargo +1.80.0 check`), the feature matrix builds, clippy/fmt, cargo-deny + cargo-vet for supply-chain (the curl|bash + crate-dep exposure), reproducible-build notes, and gating the libSQL crate behind its own scoped waiver. Concrete GitHub Actions outline.' },
]

phase('Research')
log('Researching 7 ops/deployment topics...')
const researched = await pipeline(
  TOPICS,
  async (t) => {
    const r = await agent(CTX + '\n\nTOPIC: ' + t.title + '\n' + t.q + '\n\nResearch concretely (web + read the repos as needed); return sourced findings + a recommended design for env-ctl.',
      { label: 'research:' + t.slug, phase: 'Research', agentType: 'Explore' })
    return { t, r }
  },
  async (prev, _o, i) => {
    const n = String(i + 1).padStart(2, '0')
    const path = REPO + '/docs/ops/' + n + '-' + prev.t.slug + '.md'
    const res = await agent(
      'Write a concrete ops/deployment design doc to EXACTLY ' + path + ' (create docs/ops/). Title "# env-ctl ops — ' + prev.t.title + '". Include: the recommended design for THIS system, concrete config/unit/command snippets, security rationale tied to the threat model, sourced facts (inline URLs), and open questions. After writing, RETURN the path.\n\n' + CTX + '\n\nFINDINGS:\n' + prev.r,
      { label: 'write:' + prev.t.slug, phase: 'Write' })
    return res
  },
)
log('Ops research fleet wrote ' + researched.filter(Boolean).length + ' docs under docs/ops/.')
return { written: researched.filter(Boolean) }