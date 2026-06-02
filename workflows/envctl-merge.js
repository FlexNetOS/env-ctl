export const meta = {
  name: 'envctl-merge',
  description: 'Unify, connect, and integrate env-ctl into the envctl workspace (crates + deps + CLI + manifest), in an isolated worktree, verify-green',
  phases: [
    { title: 'Map', detail: 'read both repos: envctl structure/manifest + env-ctl crates/merge-intent' },
    { title: 'Plan', detail: 'exact merge plan: crate moves, dep union, CLI fold, manifest components, gates' },
    { title: 'Execute', detail: 'apply the merge in a fresh envctl worktree branch; build + test green' },
    { title: 'Verify', detail: 'adversarial review: regressions, gates, collisions, manifest' },
  ],
}

// ---- EDIT THESE TWO PATHS IF THE REPOS MOVE ----
const ENVCTL = '/home/drdave/Desktop/envctl'        // merge TARGET (the env manager)
const SRC = '/home/drdave/Desktop/env-ctl'          // merge SOURCE (this secrets repo)

const RULES = `TARGET = ${ENVCTL} (envctl: a pure-Rust, stable, declarative TOML-component env manager — workspace crates engine/cli/gui, the 5 verbs auto-detect/install/auto-fix/reset/add-repo, Component/Hook/Wiring/Guard model, dry-run-by-default for destructive verbs, engine never prints). SOURCE = ${SRC} (env-ctl: the audited secrets vault + credential broker — FIVE workspace member crates: secrets-engine (lib envctl_secrets, pure-Rust C-free), secrets-proto, secretd, secretctl, AND secrets-store-libsql (the libSQL "remote" Store — OI-1 RESOLVED (a): it is now a [workspace.members] entry, and secretd runtime-selects it as a config-selectable durable backend; it depends on hyper 0.14 + libsql). env-ctl ALSO ships ci/gates/no-c.sh + ci/gates/shape.sh (the cargo-metadata-based no-C-LIBRARY + single-ring-rustls gates) and docs/ops/08-secretd-store-config.md.). Goal: env-ctl becomes part of the envctl workspace WITHOUT regressing envctl. Crate package names are collision-free (envctl-secrets-engine / -proto / envctl-secretd / envctl-secretctl / envctl-secrets-store-libsql vs envctl-engine / envctl / envctl-gui). Honor the UPHELD tenet: NO C *LIBRARY* in any merged crate's tree (no libsql-ffi/libsql-sys/sqlite3-sys/openssl-sys/aws-lc) — a build-time C TOOLCHAIN (cc) IS accepted (already needed by ring + blake3, and by libsql's lemon.c parser-generator); exactly one rustls on the ring path; MSRV 1.80; dry-run-by-default. Carry env-ctl's ci/gates/* into envctl's CI. Do NOT auto-commit to envctl master — land in a branch/worktree for operator review.`

const MAP_SCHEMA = { type: 'object', additionalProperties: false, properties: { area: { type: 'string' }, findings: { type: 'string', description: 'concrete facts: file paths, workspace members, dependency rows + versions/features, CLI/clap structure, manifest component shape, collisions, and anything that affects the merge.' } }, required: ['area', 'findings'] }
const PLAN_SCHEMA = { type: 'object', additionalProperties: false, properties: {
  crate_moves: { type: 'string', description: 'exact: which SRC crate dirs move to which ENVCTL/crates/ paths (ALL FIVE incl. secrets-store-libsql, which is a [workspace.members] entry that secretd depends on — it MUST move too); also carry SRC ci/gates/* and docs/ops/08; any path/import rewrites needed.' },
  workspace_cargo: { type: 'string', description: 'the merged root Cargo.toml: [workspace.members] additions (all five secrets crates) and the [workspace.dependencies] UNION (resolve conflicts: rustix -> ["process","net","time"] union per HF-17; add the secrets crypto/tonic/tokio/hyper/etc. rows; add libsql {default-features=false, features=["remote"]}, hyper 0.14, and the internal envctl-secrets-store-libsql path dep). Show the exact resulting rows.' },
  cli_fold: { type: 'string', description: 'how the secretctl verbs join the envctl CLI: either fold the secret/relay/ca/run/lock/audit subcommands under the `envctl` binary, OR keep secretd + secretctl as additional workspace bins (recommend + justify). Keep envctl ergonomics (--json, dry-run-by-default).' },
  manifest_components: { type: 'string', description: 'the new envctl manifest component(s) (per SRC/docs/ops/02-envctl-component.md) so `envctl install env-ctl` builds + installs secretd/secretctl (+ optional sqld) and wires the run integration reversibly; enable=false until the daemon is production-ready; detect/verify/fix/remove hooks; data_paths/config_paths for guarded purge.' },
  gates_and_risks: { type: 'string', description: 'CI gate union (per-crate no-C-LIBRARY, single rustls/ring, MSRV 1.80, feature matrix); merge risks (Cargo.lock unification, dep-version conflicts, doc moves) + how the Execute step verifies green.' },
}, required: ['crate_moves', 'workspace_cargo', 'cli_fold', 'manifest_components', 'gates_and_risks'] }
const FIND_SCHEMA = { type: 'object', additionalProperties: false, properties: { lens: { type: 'string' }, findings: { type: 'array', items: { type: 'object', additionalProperties: false, properties: { severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low'] }, issue: { type: 'string' }, fix: { type: 'string' }, confidence: { type: 'string', enum: ['high', 'medium', 'low'] } }, required: ['severity', 'issue', 'fix', 'confidence'] } } }, required: ['lens', 'findings'] }

phase('Map')
log('Reading both repos...')
const MAP = [
  { area: 'envctl-structure', q: `Read ${ENVCTL}/Cargo.toml, ${ENVCTL}/crates/{engine,cli,gui}/Cargo.toml + cli/src/main.rs (the clap tree), ${ENVCTL}/rust-toolchain.toml, ${ENVCTL}/docs/ARCHITECTURE.md + PRD.md. Report the workspace members, the full [workspace.dependencies] rows (versions+features), the CLI subcommand structure (where new verbs fold), and any constraints (no-web, stable, deps discipline).` },
  { area: 'envctl-manifest', q: `Read ${ENVCTL}/crates/engine/src/{component.rs,model.rs,wiring.rs,guard.rs} + 1-2 ${ENVCTL}/manifest/*.toml examples. Report the EXACT Component/Hook/Wiring/Guard TOML shape (kinds, fields), how install/detect/verify/fix/remove hooks + data_paths/config_paths work, so secrets components can be authored faithfully.` },
  { area: 'env-ctl-crates', q: `Read ${SRC}/Cargo.toml + each ${SRC}/crates/*/Cargo.toml (incl. secrets-store-libsql). Report every package name, its deps+features, lib/bin, and the secrets-store-libsql conditional state (in/out of workspace). Flag any dependency-version deltas vs envctl that the union must resolve.` },
  { area: 'env-ctl-merge-intent', q: `Read ${SRC}/docs/CHARTER.md, ${SRC}/docs/DESIGN-NOTES.md (esp. OI-1 + HF-17 rustix), ${SRC}/docs/ops/02-envctl-component.md, ${SRC}/HANDOFF.md. Report the planned merge mechanics, the OI-1 store decision state, and the envctl-component design the manifest step should follow.` },
]
const maps = (await parallel(MAP.map((m) => () =>
  agent(`${RULES}\n\nMAP AREA: ${m.area}\n${m.q}\nRead-only; report concrete facts.`, { label: 'map:' + m.area, phase: 'Map', agentType: 'Explore', schema: MAP_SCHEMA })
))).filter(Boolean)

phase('Plan')
log('Synthesizing the merge plan...')
const plan = await agent(`${RULES}\n\nProduce the EXACT, executable merge plan per schema, from the repo maps below. Resolve every dependency-union conflict explicitly. secrets-store-libsql IS already a [workspace.members] entry in SRC (OI-1 RESOLVED (a)) and is wired into secretd as a config-selectable durable backend — MOVE it too, add libsql + hyper 0.14 + the envctl-secrets-store-libsql path dep to the union, and carry env-ctl's ci/gates/* (the metadata-based no-C-LIBRARY gate, which accepts a build-time cc but forbids any C library) + docs/ops/08-secretd-store-config.md. Prefer keeping secretd + secretctl as workspace bins and folding their verbs into envctl's CLI as a thin dispatch (justify your choice).\n\nREPO MAPS (JSON):\n${JSON.stringify(maps)}`, { label: 'plan', phase: 'Plan', schema: PLAN_SCHEMA })

phase('Execute')
log('Applying the merge in an isolated envctl worktree branch...')
const exec = await agent(`Execute the merge plan below into an ISOLATED git worktree of envctl (do NOT touch envctl's working tree or master). Steps:\n1. Bash: create a worktree branch — git -C ${ENVCTL} worktree add ../envctl-merge-envctl -b merge/env-ctl (pick a free path under ~/Desktop; if it exists, reuse or add a suffix). Report the worktree path.\n2. Copy ALL FIVE SRC crates into <worktree>/crates/ per the plan (cp -r ${SRC}/crates/<x> ...; STRIP each crate's own target/). secrets-store-libsql IS a member (OI-1 (a)) — move it too. ALSO copy ${SRC}/ci/gates/ into <worktree>/ci/gates/ (chmod +x) and ${SRC}/docs/ops/08-secretd-store-config.md into envctl's docs.\n3. Edit <worktree>/Cargo.toml: add the new [workspace.members] (all five) + apply the [workspace.dependencies] UNION exactly as the plan specifies (rustix process,net,time union; add the secrets rows incl. libsql {default-features=false, features=["remote"]}, hyper 0.14, and the envctl-secrets-store-libsql path dep).\n4. Apply the CLI fold + author the manifest component(s) per the plan (enable=false).\n5. Build + test IN THE WORKTREE: cargo build --workspace; cargo test --workspace (expect ~118 passing; the libSQL sqld-backed tests are #[ignore]d); then run the CARRIED gates: bash ci/gates/no-c.sh (metadata-based: proves NO C library + exactly one ring-only rustls, accepting a build-time cc) and bash ci/gates/shape.sh. Iterate until GREEN. Do NOT commit.\nReturn: the worktree path + branch, the exact commands run, the final test counts, the gate results, and any deviations from the plan.\n\n${RULES}\n\nMERGE PLAN (JSON):\n${JSON.stringify(plan)}`, { label: 'execute', phase: 'Execute' })

phase('Verify')
log('Adversarial review of the merged worktree...')
const LENSES = [
  `Regression: does envctl's existing engine/cli/gui still build + pass its tests unchanged in the merged worktree? Did the [workspace.dependencies] union silently bump any envctl dep (esp. the rustix feature union, serde/clap/etc.)? Any behavior change to the 5 verbs?`,
  `Secrets integrity + gates: do the merged secrets crates build + pass their ~118 tests (libSQL sqld-backed tests #[ignore]d)? Does the carried ci/gates/no-c.sh pass — NO C LIBRARY (libsql-ffi/libsql-sys/sqlite3-sys/openssl-sys/aws-lc) anywhere, exactly one ring-only rustls 0.23, ring present — accepting that a build-time cc IS used (ring/blake3/libsql lemon.c)? secrets-store-libsql is a member + wired into secretd (NOT held out) — confirm it built. MSRV 1.80? ci/gates/shape.sh pass?`,
  `Surface + manifest: are there crate-name / bin-name / CLI-verb collisions? Is the new manifest component faithful to envctl's Component/Hook/Wiring/Guard shape, enable=false, with correct detect/verify/fix/remove + guarded data_paths/config_paths? Is anything claimed-wired actually still todo!()?`,
]
const reviews = (await parallel(LENSES.map((l, i) => () =>
  agent(`Adversarially review the env-ctl -> envctl merge in the worktree (path is in the EXECUTE report) through this lens:\n${l}\nRead the merged files. Concrete flaws + fixes; default to reporting when uncertain.\n\nEXECUTE REPORT:\n${exec}\n\n${RULES}`, { label: 'verify:' + i, phase: 'Verify', schema: FIND_SCHEMA })
))).filter(Boolean)

log('Merge staged in a worktree branch + reviewed. Land it after operator review.')
return { plan, exec, reviews }