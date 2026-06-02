export const meta = {
  name: 'env-ctl-research-fleet',
  description: 'Verified deep-research on 15 env-ctl security primitives + library specifics; one cited reference doc per topic',
  phases: [
    { title: 'Research', detail: '2 web researchers per topic (broad + deep)' },
    { title: 'Verify', detail: 'adversarial fact-check of each topic' },
    { title: 'Write', detail: 'cited reference doc per topic under docs/research/' },
  ],
}

const REPO = '/home/drdave/Desktop/env-ctl'
const CTX = 'Context: env-ctl is a pure-Rust local-+server secrets vault + credential BROKER (virtual-credit-card relay model) on Ubuntu 26.04; libSQL store, app-layer XChaCha20-Poly1305, argon2id keyslots, USB-partition-UUID unlock, gRPC-over-UDS control + HTTPS relay data plane, local CA for MITM, <=24h USB-gated relay bearers. Design docs live in ' + REPO + '/docs/. Your job: produce CURRENT, SOURCED facts (the assistant knowledge cutoff is Jan 2026 — verify versions/APIs against the live web). ALWAYS use web search + fetch real pages; cite every nontrivial claim with a URL. Flag anything you could not verify.'

const TOPICS = [
  { slug: 'aead-at-rest', title: 'XChaCha20-Poly1305 at-rest envelope in Rust', q: 'The chacha20poly1305 crate (XChaCha20Poly1305): API, 24-byte nonce generation + uniqueness strategy, AAD binding, handling large secret bodies, streaming AEAD vs one-shot, common misuse. Compare vs AES-256-GCM-SIV. Best practice for a per-record sealed envelope keyed by a DEK.' },
  { slug: 'argon2id-keyslots', title: 'argon2id params + LUKS-style keyslots', q: 'The argon2 Rust crate API; recommended argon2id m/t/p params for interactive vault unlock on a 256GB+ RAM box; OWASP/RFC9106 guidance; LUKS2 keyslot design (a master key wrapped under multiple KEKs); how to wrap one DEK under both a USB-keyfile KEK (HKDF) and a passphrase KEK (argon2id).' },
  { slug: 'libsql-server', title: 'libSQL/Turso: embedded vs sqld vs remote client', q: 'libSQL Rust crate (libsql): local, remote (HTTP/hrana), and embedded-replica modes; cargo features and which avoid bundling C sqlite3.c; sqld/turso server; embedded replica sync semantics + conflict handling; encryption-at-rest options; security posture for hosting a secrets DB; current version.' },
  { slug: 'usb-partuuid-detect', title: 'USB key detection by PARTUUID on Linux', q: 'Detecting a specific USB partition by GPT PARTUUID on Linux: /dev/disk/by-partuuid, blkid, udev hotplug events vs polling, the udev/libudev Rust crates, mounting/reading a keyfile, and proving possession of high-entropy keyfile contents (not just UUID match). Hotplug-driven auto-lock on removal.' },
  { slug: 'process-hardening', title: 'Secret process hardening in Rust', q: 'mlockall(MCL_CURRENT|MCL_FUTURE), RLIMIT_CORE=0, prctl(PR_SET_DUMPABLE,0), ptrace/YAMA protection, disabling swap of secret pages, the zeroize crate (Zeroizing, ZeroizeOnDrop) guarantees + limits, secrecy crate; how to do these via rustix/libc on Linux; pitfalls (mlock limits, fork, core dumps).' },
  { slug: 'grpc-uds-peercred', title: 'tonic gRPC over UDS + SO_PEERCRED authz', q: 'Serving tonic gRPC over a Unix-domain socket (tokio UnixListener, tower); reading SO_PEERCRED (struct ucred: uid/gid/pid) via rustix/libc getsockopt on the accepted connection; a tower interceptor that refuses uid != owner; current tonic 0.12+ patterns + any 0.13 changes.' },
  { slug: 'rustls-mitm-ca', title: 'rustls intercepting proxy + on-the-fly leaf certs', q: 'Building an HTTPS MITM/intercepting proxy in Rust with rustls 0.23 (ring CryptoProvider): per-SNI on-the-fly leaf minting with rcgen 0.13, leaf cache, ResolvesServerCert; CONNECT handling with hyper 1.x; CRITICALLY keep verification to the REAL upstream intact (webpki-roots). Security pitfalls of a private CA. Current APIs.' },
  { slug: 'anthropic-proxy', title: 'Anthropic API base-URL proxy + streaming', q: 'ANTHROPIC_BASE_URL / base_url support in the Anthropic SDKs + claude CLI; the Messages API auth header (x-api-key vs Authorization: Bearer); SSE streaming format and how a proxy must pass it through unbuffered; rate-limit headers; any gotchas proxying claude/Claude Code through a local endpoint.' },
  { slug: 'github-subtokens', title: 'GitHub native scoped sub-tokens', q: 'Can GitHub fine-grained PATs be minted via API? GitHub App installation access tokens (POST /app/installations/{id}/access_tokens) — scopes, repository selection, ~1h TTL; how a broker could mint short-lived scoped tokens from an App private key (JWT). gh CLI auth + GH_TOKEN. What is genuinely upstream-native vs needs proxy.' },
  { slug: 'openai-subtokens', title: 'OpenAI base-URL + scoped keys', q: 'OPENAI_BASE_URL / base_url support; project API keys vs admin keys; can scoped/short-lived keys be minted via the Admin API; auth header format; streaming. Applicability to the relay swap + native-sub-token path.' },
  { slug: 'ca-trust-wiring', title: 'Per-tool CA trust-store wiring', q: 'Exact semantics + precedence of NODE_EXTRA_CA_CERTS, REQUESTS_CA_BUNDLE (+ CURL_CA_BUNDLE), GIT_SSL_CAINFO, SSL_CERT_FILE/SSL_CERT_DIR, and update-ca-certificates on Ubuntu; which tools honor which; how to wire reversibly (owned files + guarded blocks) and revert cleanly; risks of adding a CA to the system bundle.' },
  { slug: 'remote-token-binding', title: 'Sender-constrained tokens without peer-cred', q: 'Binding a bearer to a remote client without SO_PEERCRED: mTLS client-cert binding, OAuth DPoP (RFC 9449), mutual-TLS sender-constrained tokens (RFC 8705), token binding, source-IP pinning tradeoffs. Which fits a <=24h relay bearer used by a Telegram cloud agent. Replay/theft resistance.' },
  { slug: 'tamper-evident-audit', title: 'Tamper-evident hash-chained audit logs', q: 'Designing a tamper-evident append-only audit log: per-row hash chain (row_hash = H(prev_hash || row)), detecting truncation/rollback/reordering, Merkle tree vs linear chain, optional external anchoring/notarization, verifying the chain on startup. Rust impl with sha2/blake3.' },
  { slug: 'secrets-prior-art', title: 'Prior art: secrets brokers + machine identity', q: 'How HashiCorp Vault dynamic secrets + response-wrapping, Infisical, Doppler, 1Password Connect/Service Accounts, SPIFFE/SPIRE, Teleport Machine ID, and sigstore handle: short-lived credential issuance, per-client scoping, revocation, and brokering a real secret behind a proxy. What to borrow for env-ctl relay/broker.' },
  { slug: 'vps-secrets-posture', title: 'Secrets-at-rest on a VPS + remote unlock', q: 'Security posture of hosting an (app-encrypted) secrets DB on a VPS; how others handle the "unlock factor cannot be physically present on the server" problem (remote attestation, TPM/Nitro/SEV-SNP, operator-box-authorizes-issuance, Shamir/auto-unseal like Vault); tradeoffs for env-ctl USB-gating on a VPS.' },
]

const SCHEMA_FINDINGS = {
  type: 'object', additionalProperties: false,
  properties: {
    summary: { type: 'string' },
    facts: { type: 'array', items: { type: 'object', additionalProperties: false, properties: {
      claim: { type: 'string' }, source_url: { type: 'string' }, confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
    }, required: ['claim', 'source_url', 'confidence'] } },
    versions: { type: 'string', description: 'current crate/API versions found' },
    open_questions: { type: 'array', items: { type: 'string' } },
  },
  required: ['summary', 'facts'],
}

phase('Research')
log('Researching ' + TOPICS.length + ' env-ctl security topics (2 web researchers each)...')

const docs = await pipeline(
  TOPICS,
  // stage A: two researchers per topic (broad survey + deep API/version dive), combined.
  async (topic) => {
    const pair = await parallel([
      () => agent(CTX + '\n\nTOPIC: ' + topic.title + '\nResearch (BROAD survey + prior art + security tradeoffs): ' + topic.q, { label: 'broad:' + topic.slug, phase: 'Research', agentType: 'Explore', schema: SCHEMA_FINDINGS }),
      () => agent(CTX + '\n\nTOPIC: ' + topic.title + '\nResearch (DEEP: exact current crate versions, API signatures, code-level specifics, gotchas): ' + topic.q, { label: 'deep:' + topic.slug, phase: 'Research', agentType: 'Explore', schema: SCHEMA_FINDINGS }),
    ])
    return { topic, research: pair.filter(Boolean) }
  },
  // stage B: adversarial fact-check.
  async (prev) => {
    const verdict = await agent(
      CTX + '\n\nTOPIC: ' + prev.topic.title + '\nADVERSARIALLY fact-check the two research outputs below: which claims are well-sourced vs unverified/outdated/wrong? Re-search anything dubious. Produce a corrected, de-duplicated, CITED fact set + a clear recommendation for env-ctl.\n\nRESEARCH (JSON):\n' + JSON.stringify(prev.research),
      { label: 'verify:' + prev.topic.slug, phase: 'Verify', agentType: 'Explore' })
    return { topic: prev.topic, verdict }
  },
  // stage C: write the reference doc (needs Write -> default agent).
  async (prev, _orig, i) => {
    const n = String(i + 1).padStart(2, '0')
    const path = REPO + '/docs/research/' + n + '-' + prev.topic.slug + '.md'
    const res = await agent(
      'Write a polished, CITED reference doc to EXACTLY this path with the Write tool: ' + path + '\n' +
      'Title it "# env-ctl research — ' + prev.topic.title + '". Structure: TL;DR recommendation for env-ctl; key facts (with inline source URLs); current versions/APIs; security tradeoffs; concrete guidance for the env-ctl implementation; open questions. Be precise and skimmable. After writing, RETURN just the path.\n\n' +
      CTX + '\n\nVERIFIED FINDINGS:\n' + prev.verdict,
      { label: 'write:' + prev.topic.slug, phase: 'Write' })
    return res
  },
)

log('Research fleet wrote ' + docs.filter(Boolean).length + ' reference docs under docs/research/.')
return { written: docs.filter(Boolean) }