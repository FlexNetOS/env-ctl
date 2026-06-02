export const meta = {
  name: 'env-ctl-audit-fixes',
  description: 'Fix audit H-1 (monotonic audit-head anchor) + M-1 (put_secret version monotonicity) + schema.sql drift, with regression tests',
  phases: [
    { title: 'Design', detail: 'design the monotonic anchor honestly, no overclaim' },
    { title: 'Implement', detail: 'apply H-1 + M-1 + schema.sql drift + tests' },
    { title: 'Review', detail: 'two reviewers: real detection? overclaim?' },
    { title: 'Fix', detail: 'fold fixes; all tests pass' },
  ],
}
const REPO = '/home/drdave/Desktop/env-ctl'
const ENG = REPO + '/crates/secrets-engine'
const RULES = `Engine = ${ENG}. Pure Rust, MSRV 1.80, async-free [dependencies], engine stays C-free. Preserve public API; keep all 90 existing tests passing and the engine C-free + async-free. MACs use blake3 (derive_key / keyed_hash); constant-time compare uses subtle; add NO new deps. BE HONEST: a full store-plus-snapshot rollback (a consistent old chain + old anchor + old high-water together) CANNOT be detected by any purely in-store mechanism — do NOT claim otherwise. The in-store fix catches partial or inconsistent truncation; the residual (full-snapshot rollback) MUST be documented as needing off-box anchoring (an Ed25519 chain-head published off-box, or an external monotonic store; see research/13) and recorded in THREAT-MODEL.md under adversary A2.`

const DSCHEMA = { type: 'object', additionalProperties: false, properties: {
  approach: { type: 'string', description: 'the monotonic anchor design: which high-water / issuance counter to bind into the audit-head MAC, how verify must match the TAIL (not any row) AND reject a current max-seq below the high-water, how the high-water resists in-store rollback as far as feasible, and the EXACT residual that remains.' },
  signatures: { type: 'string', description: 'the changed fn signatures: audit_head_mac, verify_audit_anchor_with, the advance path, any new META keys, and the put_secret M-1 assertion.' },
  tests: { type: 'string', description: 'regression tests: truncate-and-replay-stale-anchor (assert what is vs is not detected); honest append+verify passes; put_secret rejects a non-monotonic version.' },
}, required: ['approach', 'signatures', 'tests'] }

const FSCHEMA = { type: 'object', additionalProperties: false, properties: { lens: { type: 'string' }, findings: { type: 'array', items: { type: 'object', additionalProperties: false, properties: { severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low'] }, issue: { type: 'string' }, fix: { type: 'string' }, confidence: { type: 'string', enum: ['high', 'medium', 'low'] } }, required: ['severity', 'issue', 'fix', 'confidence'] } } }, required: ['lens', 'findings'] }

phase('Design')
const design = await agent(`Design the fix for audit finding H-1 (and M-1). Read ${REPO}/docs/audits/AUDIT-phase1.md (H-1 near lib.rs verify_audit_anchor_with ~1418-1440, audit_head_mac ~1605, advance ~291 and ~1392, META_AUDIT_HEAD; M-1 at store.rs put_secret ~228), ${ENG}/src/lib.rs, ${ENG}/src/vault/audit.rs, ${ENG}/src/vault/store.rs. Produce the design per schema. The audit is explicit: matching the last row ALONE is insufficient; bind a strictly-increasing high-water / issuance counter and reject anchors at or below it. Be honest about the residual.\n\n${RULES}`, { label: 'design', phase: 'Design', schema: DSCHEMA })

phase('Implement')
const impl = await agent(`Implement the H-1 + M-1 fix per the DESIGN below (Read each file first, then Edit/Write):\n- ${ENG}/src/lib.rs: monotonic audit-head anchor — bind a high-water into audit_head_mac; verify must match the TAIL and reject a current max-seq below the high-water; advance updates the high-water monotonically.\n- ${ENG}/src/vault/store.rs: M-1 — put_secret asserts row.version equals max_secret_version(name)+1 (or 1 when none) and bails otherwise.\n- ${ENG}/src/vault/audit.rs if needed.\n- ${ENG}/tests/vault.rs: add the regression tests.\n- ${REPO}/docs/db/schema.sql: fix the audit-hash comment drift — it is blake3(prev_hash concatenated with canonical_row) with a DOMAIN-SEPARATED genesis prev_hash (NOT zeroes); match audit.rs.\n- ${REPO}/docs/THREAT-MODEL.md: record the full-snapshot-rollback residual under A2 plus the off-box-anchoring mitigation path.\nKeep all 90 existing tests passing.\n\nDESIGN (JSON):\n${JSON.stringify(design)}\n\n${RULES}`, { label: 'implement', phase: 'Implement' })

phase('Review')
const LENSES = [
  `Correctness: does the new anchor ACTUALLY detect the H-1 attack (truncate the chain then replay a captured-earlier anchor), or only the easy partial case? Trace the exact attacker steps against the new verify. Is the high-water genuinely harder to roll back than the chain, or is the claim hollow? Flag any OVERCLAIM versus the honest residual.`,
  `Regression and no-break: do the new tests prove detection (not just pass trivially)? Does M-1 reject non-monotonic versions without breaking legitimate version bumps? Do all 90 prior tests still pass? Engine still C-free and async-free, no new deps, public API intact?`,
]
const reviews = (await parallel(LENSES.map((l, i) => () =>
  agent(`Adversarially review the env-ctl audit fix through this lens:\n${l}\nRead the changed files under ${ENG}/src/ and tests/vault.rs and the AUDIT-phase1.md H-1 entry. Concrete flaws plus fixes; default to reporting when uncertain.\n\nIMPLEMENT NOTES:\n${impl}`, { label: 'review:' + i, phase: 'Review', schema: FSCHEMA })
))).filter(Boolean)

phase('Fix')
const fixed = await agent(`Finalize the audit fix: read the files plus the review findings, apply confirmed fixes, ensure the engine compiles and ALL tests pass (lib unit + phase0 + vault + relay), engine C-free and async-free, and NO overclaim in comments or docs.\nFiles: ${ENG}/src/lib.rs, ${ENG}/src/vault/audit.rs, ${ENG}/src/vault/store.rs, ${ENG}/tests/vault.rs, ${REPO}/docs/db/schema.sql, ${REPO}/docs/THREAT-MODEL.md.\n\nFINDINGS (JSON):\n${JSON.stringify(reviews)}\n\n${RULES}`, { label: 'fix', phase: 'Fix' })
log('Audit H-1/M-1 fix complete.')
return { design, impl, reviews, fixed }