export const meta = {
  name: 'env-ctl-phase1-vaultcore',
  description: 'Implement + adversarially review the backend-agnostic crypto core (AEAD, AAD, keyslots, bearer MAC) replacing Phase-0 todo!() bodies',
  phases: [
    { title: 'Implement', detail: '4 agents implement crypto/aad/keyslot/token for real + KAT tests' },
    { title: 'Review', detail: '4 adversarial crypto reviewers' },
    { title: 'Fix', detail: 'fold confirmed fixes into the files' },
  ],
}

const REPO = '/home/drdave/Desktop/env-ctl'
const RULES = [
  'Engine = ' + REPO + '/crates/secrets-engine. PURE RUST, stable rustc, MSRV 1.80. Use ONLY deps already in that crate Cargo.toml: chacha20poly1305 0.10 (features alloc,getrandom,rand_core), argon2 0.5, hkdf 0.12, sha2 0.10, blake3 1.5, zeroize 1.8, subtle 2.6, rand 0.8, getrandom 0.2, serde, serde_json, toml, anyhow, thiserror, chrono. DO NOT add any new dependency.',
  'MACs: use blake3::keyed_hash(&[u8;32], data) (a keyed MAC) — there is NO hmac crate available; do not add one.',
  'Constant-time comparisons: use subtle (ConstantTimeEq).',
  'Nonces: XChaCha20Poly1305 24-byte nonce from a CSPRNG (chacha20poly1305::aead::OsRng via generate_nonce). Never reuse, never seed outside #[cfg(test)].',
  'PRESERVE every existing `pub` fn/struct/enum signature EXACTLY (the crate lib.rs re-exports depend on them). Implement bodies, add PRIVATE helpers + #[cfg(test)] unit tests with known-answer vectors. Keep the engine async-free.',
  'Ground every choice in the matching ' + REPO + '/docs/research/ doc (read it). The code MUST compile on stable and tests should pass; prefer correctness + clarity.',
  'Write the COMPLETE updated file back to its path with the Write tool. Return a short note of what you implemented + any caveat.',
].join('\n')

const MODS = [
  { key: 'crypto', file: 'crates/secrets-engine/src/vault/crypto.rs', research: 'docs/research/01-aead-at-rest.md',
    instr: 'Implement seal(dek:&Dek, aad:&[u8], plaintext:&[u8]) -> (Vec<u8> /*nonce24*/, Vec<u8> /*ct||tag*/) and open(dek:&Dek, aad:&[u8], nonce:&[u8], ct_tag:&[u8]) -> Option<Vec<u8>>. Use XChaCha20Poly1305 (key = Dek.0, 32 bytes), a fresh 24-byte OsRng nonce per seal, AAD authenticated-not-encrypted. open returns None on tag failure / bad nonce length. Add a KAT test from the CFRG XChaCha20-Poly1305 draft vectors AND a round-trip + tamper-detection test (flip a ct byte => None; wrong AAD => None).' },
  { key: 'aad', file: 'crates/secrets-engine/src/vault/aad.rs', research: 'docs/research/01-aead-at-rest.md',
    instr: 'Implement record_aad(tag:TableTag, row_id:u64, version:u64, dek_generation:u64) -> Vec<u8> as a FIXED-WIDTH canonical encoding: a domain-separation prefix b"env-ctl/v1/aad" then u8(tag) then u64-big-endian(row_id), u64be(version), u64be(dek_generation). No var-int/length-prefix ambiguity. Add a golden-bytes test asserting the exact layout, and a test that two different (tag,id,version,gen) tuples never collide.' },
  { key: 'keyslot', file: 'crates/secrets-engine/src/keyslot.rs', research: 'docs/research/02-argon2id-keyslots.md',
    instr: 'Implement: keyslot_aad(&Keyslot)->Vec<u8> (fixed-width canonical over factor,kdf-id+params,salt(len-prefixed),usb_partition_uuid(len-prefixed),dek_generation,id); kek_from_usb(&Zeroizing<Vec<u8>>,&[u8]) -> Kek via Hkdf::<Sha256>::new(Some(salt),keyfile).expand(b"env-ctl/v1/kek/usb", &mut [0u8;32]); kek_from_passphrase(&Zeroizing<Vec<u8>>,&[u8],Argon2Params)->Kek via Argon2::new(Algorithm::Argon2id,Version::V0x13,Params::new(m_kib,t_cost,p_lanes,Some(32))).hash_password_into(...), and HARD-FAIL (panic or documented) if m_kib < ARGON2_M_KIB_FLOOR; wrap_dek(Kek,&Dek,&[u8])->(Vec<u8>,Vec<u8>) and unwrap_dek(Kek,&[u8],&[u8],&[u8])->Option<Dek> using XChaCha20Poly1305 keyed by the KEK with the keyslot AAD (consume the Kek by value); header_mac(&Dek,&[Keyslot],i64)->Vec<u8> via blake3::keyed_hash over a canonical encoding of all slots + issuance_floor. Add tests: wrap then unwrap round-trips; unwrap with the WRONG kek => None; a tampered keyslot AAD => None; argon2 below floor is rejected; header_mac changes when a slot is added/removed.' },
  { key: 'token', file: 'crates/secrets-engine/src/broker/token.rs', research: 'docs/research/12-remote-token-binding.md',
    instr: 'Implement verify_bearer(hmac_key:&[u8;32], presented:&str, stored_mac:&[u8]) -> bool: compute blake3::keyed_hash(hmac_key, presented.as_bytes()), compare its 32 bytes to stored_mac in CONSTANT TIME via subtle::ConstantTimeEq (handle length mismatch as false without early-return timing leak). Add a helper mac_bearer(hmac_key,&str)->[u8;32] for the mint side. Tests: correct token verifies; any single-bit change fails; wrong key fails; wrong-length stored_mac fails. (DPoP sender-binding is server-mode/Phase 6 — do NOT implement it here; just the base keyed-MAC verify.)' },
]

const FIND = {
  type: 'object', additionalProperties: false,
  properties: {
    module: { type: 'string' },
    compiles_concern: { type: 'string', description: 'any reason it might not compile on the pinned versions' },
    findings: { type: 'array', items: { type: 'object', additionalProperties: false, properties: {
      severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low'] },
      issue: { type: 'string' }, fix: { type: 'string' }, confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
    }, required: ['severity', 'issue', 'fix', 'confidence'] } },
  },
  required: ['module', 'findings'],
}

phase('Implement')
log('Implementing 4 backend-agnostic crypto-core modules...')
const impls = (await parallel(MODS.map(m => () =>
  agent('Implement the env-ctl module `' + m.key + '` (file ' + REPO + '/' + m.file + ').\nFirst Read that file (for exact signatures) and ' + REPO + '/' + m.research + '.\n\nTASK: ' + m.instr + '\n\n' + RULES,
    { label: 'impl:' + m.key, phase: 'Implement' })
))).filter(Boolean)

phase('Review')
log('4 adversarial crypto reviewers auditing the implementations...')
const reviews = (await parallel(MODS.map(m => () =>
  agent('Adversarially review the env-ctl crypto module `' + m.key + '` at ' + REPO + '/' + m.file + ' (Read it + ' + REPO + '/' + m.research + ').\nHunt for: wrong/missing AAD binding, nonce reuse or wrong size, non-constant-time compares, missing zeroization, KDF param/floor bugs, argon2/hkdf/chacha API misuse on the PINNED versions (chacha20poly1305 0.10, argon2 0.5, hkdf 0.12), signature drift vs the Phase-0 scaffold, and anything that will not COMPILE. Give concrete fixes.',
    { label: 'review:' + m.key, phase: 'Review', schema: FIND })
))).filter(Boolean)

phase('Fix')
log('Folding confirmed fixes into the modules...')
const fixed = await agent(
  'You are finalizing the env-ctl crypto core. For EACH module, read its file + the review findings below, and APPLY all confirmed critical/high/medium fixes by Editing/Writing the file (keep pub signatures stable, keep tests). Ensure each file will compile on stable with the pinned deps and that MACs use blake3::keyed_hash, compares use subtle. Files:\n' +
  MODS.map(m => '- ' + REPO + '/' + m.file).join('\n') +
  '\n\nREVIEW FINDINGS (JSON):\n' + JSON.stringify(reviews) +
  '\n\nAfter editing, RETURN a JSON list of {file, fixes_applied:[..], residual_risk}.\n\n' + RULES,
  { label: 'fix', phase: 'Fix' })

log('Phase-1 crypto core implemented + reviewed + fixed.')
return { implementations: impls, reviews, fixed }