# env-ctl

The **security, keys, certs, auto-inject, database, and API** subsystem of
[`envctl`](../envctl) — developed in a **parallel repo** and designed to **merge in**
once it stabilizes.

`envctl` is a pure-Rust, GPU-aware environment manager for one dual-RTX-5090 Ubuntu 26.04
workstation. It deliberately declared secrets out of scope:

> **Non-Goal N6:** *Not a secrets/credentials manager. Interactive auth (`claude /login`,
> `gh auth login`) is explicitly out of scope and left to the user.*  — `envctl/docs/PRD.md`

`env-ctl` **fills exactly that gap.** It is the local, single-operator **secrets vault +
credential injector** that gives the box a safe place to store keys/certs/tokens and a
disciplined way to hand them to tools — so `gh`, `claude`, `cargo`, container builds, and
add-repo source builds get their credentials without the operator pasting secrets into
shell history or committing `.env` files.

## Scope (the six pillars)

| Pillar | What it owns |
|---|---|
| **security** | Threat model, encryption-at-rest, fail-closed access control, tamper-evident audit log. Inherits `envctl`'s boot-repair *gold standard*: resolve + re-verify, dry-run by default for destructive ops, refuse on ambiguity, back up before clobber, never touch user data. |
| **keys** | SSH keys, API tokens (Claude/gh/OpenAI/HF/…), GPG — import, generate, rotate, expire, list. |
| **certs** | Local CA, leaf/mTLS certs for the API and local services; issue, renew, revoke. |
| **auto-inject** | Hand secrets to processes as env vars / files **without** leaking them into global shell state or git. |
| **database** | Encrypted-at-rest store: secrets, metadata, versions, audit log. |
| **api** | A local daemon serving secrets to authorized clients (the CLI, `envctl`, tools). |

## Why a separate repo (for now)

`envctl` is mid-flight (Phases 0–3 dogfooded on the live box). Building the security layer
here lets it move in parallel without destabilizing the shipped engine. The two converge by
**convention-matching**, not luck:

- Same workspace metadata (edition 2021, `rust-version = 1.80`, `MIT OR Apache-2.0`).
- Same `rust-toolchain.toml` (stable + rustfmt + clippy), same `.gitignore` base.
- Same architecture spine: **one pure engine library, thin front-ends** (CLI + the daemon),
  driven by a structured `Event` stream — the engine never prints.
- Same safety discipline and fail-closed guard philosophy.

On merge, the crates here drop into `envctl/crates/` and the shared `[workspace.dependencies]`
unify. See [`docs/CHARTER.md`](docs/CHARTER.md) for the merge plan and conventions.

## Status

**Scaffolding.** Repo initialized; conventions pinned to `envctl`. Architecture and crate
layout are being designed; foundational security choices (storage/crypto backend, unlock
mechanism, API transport, injection mechanism) are being confirmed with the operator before
code lands. Nothing here stores a real secret yet.
