# env-ctl — orchestration workflows

These are the **multi-agent workflow scripts** that designed, built, and audited `env-ctl`.
They are preserved here as **provenance** (how the repo was produced) and as **reusable templates**
for the remaining phases and for the eventual `envctl` merge.

Each is a self-contained [Claude Code Workflow](https://docs.claude.com/) script
(`export const meta = {...}` + a body using `agent()` / `parallel()` / `pipeline()` / `phase()`).
The dominant pattern is **design → implement → adversarial-review → fix**, with a separate fresh-eyes
**audit** pass on security-critical surfaces, and **verified-green-then-commit** between every step.

> Paths inside the scripts are hard-coded to `/home/drdave/Desktop/env-ctl`. To re-run, adjust the
> `REPO` const (or run from a checkout at that path) and invoke with
> `Workflow({scriptPath: "workflows/<name>.js"})`.

## The build narrative (in order)

| # | Workflow | Shape | Produced |
|---|----------|-------|----------|
| 1 | `env-ctl-architecture.js` | 7 architects → synth → 6 adversarial reviewers → write | The full design: `ARCHITECTURE`, `DESIGN-NOTES`, `ROADMAP`, `THREAT-MODEL`, `SCAFFOLD-SPEC`, the `.proto`, `schema.sql` (62 review findings folded) |
| 2 | `env-ctl-research-fleet.js` | 15 topics × (2 web researchers → verify → write) | `docs/research/01..15` — verified, cited reference docs grounding every crypto/library choice |
| 3 | `env-ctl-server-mode.js` | 3 architects → 3 reviewers → write + doc-edits | `SERVER-MODE.md` (central daemon + remote relay-only edge; DPoP binding; control unreachable; VPS deferred) |
| 4 | `env-ctl-phase1-vaultcore.js` | 4 implementers → 4 reviewers → fix | Crypto core: AEAD seal/open, canonical AAD, keyslots, bearer MAC (+ KATs) |
| 5 | `env-ctl-phase1b-vault.js` | design → implement → 3 reviewers → fix | Functional vault: `init`/`unlock`/`lock`/`secret_put`/`secret_get` + audit hash chain + real `InMemStore` |
| 6 | `env-ctl-phase4-broker.js` | design → implement → 3 reviewers → fix | Credential broker: `decide()`, `relay_mint`/`relay_swap`/revoke, `CLOCK_BOOTTIME` fence |
| 7 | `env-ctl-audit-phase1.js` | 8 lenses → synth | `docs/audits/AUDIT-phase1.md` (crypto+vault; 0 critical, 1 high) |
| 8 | `env-ctl-ops-research.js` | 7 topics × (research → write) | `docs/ops/01..07` — systemd, envctl-component, USB ceremony, backup/rotation, audit signing, run UX, CI |
| 9 | `env-ctl-audit-fixes.js` | design → implement → 2 reviewers → fix | Fixes audit H-1 (monotonic audit anchor) + M-1 (version monotonicity) |
| 10 | `env-ctl-audit-servermode.js` | 6 lenses → synth | `docs/audits/AUDIT-server-mode.md` (remote-edge design; flagged the libSQL-purity overclaim, F1) |
| 11 | `env-ctl-phase6-daemon.js` | design → implement → 2 reviewers → fix | Local daemon: `secretd` gRPC/UDS + `SO_PEERCRED` + `secretctl`, e2e |
| 12 | `env-ctl-phase1-store-libsql.js` | design → implement → 2 reviewers | `secrets-store-libsql` (durable libSQL `Store`, C-free-gated) |

## Operating notes (what worked)

- **One workflow at a time on the critical path.** Over-parallelizing tripped Anthropic's
  server-side request-rate throttle, which fails runs (zero useful work). Read-only fleets
  (research/audit) were the only thing run concurrently with a code workflow, kept under ~16 agents
  total.
- **Verified-green-then-commit.** Every code phase ended with `cargo test --workspace` + the C-free /
  async-free dependency gates before a commit + push. The engine stayed pure-Rust, C-free, and
  async-free throughout.
- **Adversarial review caught real bugs** (audit-anchor truncation replay, a row_id TOCTOU, the
  libSQL "VERIFIED pure-Rust" overclaim) and **rejected false positives** (a claimed hex OOB panic).
- **Single implementer for interdependent code; parallel implementers only for independent modules.**
