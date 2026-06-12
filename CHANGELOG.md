# Changelog

All notable changes to AXR are documented here. The project follows the
spec-version scheme used throughout the codebase (0.2 stable core, 0.3 anchoring,
0.4 redactable / side-effect / trust-root, 0.5 key succession, 0.6
root-lifecycle hardening + SIEM export).

## [0.6.0] - 2026-06-12

Root-lifecycle hardening: the 0.5 root key's own lifecycle closes — quorum
signing, rotation/recovery, revocation, and a multi-party ceremony CLI.
Spec: `AXR-SPEC-0.6.md`. Scope was decided via independent Meridian/NEXUS
critiques (`AXR-0.6-SCOPE.md`); every feature is opt-in and a trust-root-less
deployment keeps the 0.3/0.4 behavior bit-for-bit.

### Added

- **Quorum root (M-of-N multi-signature)** (`axr-succession.js`:
  `signQuorumPart`/`assembleQuorum`/`verifyQuorumSigned`, quorum-mode trust
  root). Records verify with M distinct declared Ed25519 signatures over the
  same canonical body; the signature set is strictly fingerprint-ordered
  (enforced at verify time) so identical sets are byte-identical. Strict
  fail-closed: undeclared/duplicate signer, M-1 signatures, tampered body,
  unordered set, post-hoc legacy signature field all reject. Honest naming:
  multi-signature, not threshold crypto — root compromise becomes quorum
  compromise, and the spec's quorum-policy section says so. Recommended
  default 2-of-3 (not enforced; M=1/N=1 stays valid). Monitor and both
  verifiers anchor on the trust-root object (single OR quorum).
- **Root rotation and recovery** (`buildTrustRootSuccessor`,
  `verifyTrustRootChain`, `parseTrustRootInput`). A successor trust root is
  signed by the predecessor's quorum and chained via
  `predecessor_trust_root_hash`; consumers accept single-record, array or
  JSONL-chain `--trust-root` inputs, the effective root is the chain tail.
  No self-authorizing roots (a successor is never valid standalone); a 0.5
  single-key root rotates to a quorum successor (migration path). The
  monitor pins the genesis hash in its journal — a substituted,
  self-consistent attacker chain is `TRUST_ROOT_CHANGED`, fail-closed.
- **Revocation** (`key_revocation`, `--revocations` on monitor and both
  verifiers). Retires a key's signing power from `revoked_at_tree_size`
  (earliest boundary wins). Three-tier semantics enforced in JS and Python:
  anchored pre-boundary artifacts stay valid; unproven pre-boundary is
  fail-closed (a stolen old key cannot fabricate the past); post-boundary is
  `KEY_REVOKED`. Forged revocations are `REVOCATION_UNAUTHORIZED` (a
  revocation-as-DoS attempt is itself a signal). OCSF mapping extended:
  `KEY_REVOKED`/`TRUST_ROOT_CHANGED` Critical, `REVOCATION_UNAUTHORIZED`
  High.
- **Ceremony CLI** (`axr-key-succession`): `body succession|revocation|
  root-successor` → `sign` (per machine) → `assemble --verify` (refuses to
  emit a record consumers would reject — self-lockout protection); `revoke`
  builds a single-key revocation; `verify` dispatches on record_type and
  accepts raw-PEM, trust-root and chain anchors.
- 92 new assertions across five suites (quorum core, quorum e2e, root
  rotation, revocation, CLI ceremony), incl. Python cross-impl agreement on
  accept AND reject for every 0.6 mechanism.

- **OCSF Detection Finding export** (`axr-ocsf.js`; monitor `--ocsf-out
  <file|->`). Maps monitor violations and security-relevant lifecycle notices
  to OCSF 1.1.0 Detection Finding shape (class_uid 2004): the two 0.5 key
  codes become detectable events — `KEY_ROTATED_AUTHORIZED` → Informational,
  `KEY_CHANGED_UNAUTHORIZED` → Critical; equivocation/truncation/
  non-append-only/invalid trust root → Critical; unknown violation codes map
  to High (fail-closed, never silently dropped). Finding uid is a
  deterministic hash of (log_id, code, message) so SIEM-side dedup works
  across polls; all AXR specifics travel under `unmapped.axr`. Honest
  boundary: OCSF-shaped output with the required fields, not formally
  OCSF-certified. 16 assertions.
- **Generic webhook delivery** (`axr-webhook.js`; monitor `--webhook <url>`,
  `--webhook-token <bearer>`). Zero-dep HTTP(S) POST of the finding array
  with retry; http/https schemes only. Delivery is best-effort by design: a
  dead SIEM endpoint can neither silence the monitor nor fail a consistent
  log — the exit code is always the detection's. 16 assertions incl.
  end-to-end: tampered log → OCSF findings arrive at a live test server;
  unreachable endpoint → explicit notice, exit code unchanged. Hardened after
  Meridian cross-review: bearer token also accepted via
  `--webhook-token-file` or `AXR_WEBHOOK_TOKEN` env (CLI args leak via
  process list / shell history), an `http:` target prints an explicit
  plaintext warning, and the operator-config trust boundary (no built-in
  SSRF allowlist — by design) is stated in the module header.

## [0.5.0] - 2026-06-12

Key-lifecycle layer: root-anchored key succession makes legitimate rotation
distinguishable from silent key compromise, end to end (sidecar → monitor →
verifiers). Spec: `AXR-SPEC-0.5.md`. All features are opt-in; without a trust
root every tool behaves bit-for-bit as 0.4. Four security findings were caught
and closed during development by NEXUS/Meridian cross-review (noted below).

### Added

- **Key succession module** (`axr-succession.js`). Root-signed `key_succession`
  records authorize operator key rotation; genesis keys come from the extended
  trust root (per `log_id`, per role `sth`/`receipt`), so the starting point is
  root-anchored — no TOFU weakness. `buildKeyTimeline` builds a
  predecessor-linked timeline verified against the pinned root key;
  `keyAtTreeSize` resolves the valid key at any tree size (tree_size is the
  only clock — no operator-controlled wall-clock in the trust path). Missing
  root genesis degrades to fail-closed. 31 assertions incl. 9 red-team cases
  in `axr-succession-test.js`; the anchor embedding adds 17 more in
  `axr-anchor-succession-test.js`.
- **`embedded_succession` in the anchoring sidecar** (`axr-anchor.js`,
  `--succession` CLI flag). After a rotation, the successor key's FIRST STH
  embeds the full root-signed succession record, so a monitor sees the
  rotation from the log itself (withholding fix). The field is covered by both
  the STH signature and the chain hash (tamper-evident), embedding is
  idempotent (later STHs revert to the 0.3 shape), and guards reject a
  succession that does not authorize the signing key, a non-`sth` role, a
  foreign `log_id` (found in NEXUS cross-review), or signing before
  `effective_from_tree_size`. Without a succession the STH is byte-identical
  to 0.3 — proved by the unchanged anchor suite.

- **Succession-aware monitor** (`axr-monitor.js`, `--trust-root` /
  `--successions` CLI flags). With a trust root the monitor anchors trust in
  the independent root key instead of TOFU key pinning: it builds a
  root-verified key timeline (genesis from the trust root, rotations from
  `key_succession` records) and verifies every STH with the key valid at that
  STH's `tree_size`. Embedded successions are root-verified BEFORE their key
  is used for anything. New codes: `KEY_ROTATED_AUTHORIZED` (notice — rotation
  is root-authorized) and `KEY_CHANGED_UNAUTHORIZED` (violation — key change
  without root authorization, incl. forged/foreign-log successions and
  unauthorized pinned-key swaps). An invalid trust root fails closed
  (`TRUST_ROOT_INVALID`); a trust root without a genesis for the log degrades
  to the old TOFU behavior with an explicit `DEGRADED` notice. The journal
  gains `active_key_fingerprint` and `succession_chain_hash`;
  `compareJournals` reports divergent succession chains as a conflict (only
  when both journals have one — 0.3 journals stay compatible). Without a
  trust root, behavior is bit-for-bit the old TOFU pinning — proved by the
  unchanged monitor suite. 22 assertions in `axr-monitor-succession-test.js`,
  built on the production path (`runAnchor` → `pollMonitor`).

- **Rotation-spanning verification** (`axr-verify.js` check 15 + `axr_verify.py`
  mirror; `--successions` / `--log-id` flags, extended `--trust-root`). With a
  genesis-bearing trust root the verifiers build root-verified key timelines
  for both roles and verify every signature with the key of its era: receipts
  by leaf position (`leaf_index+1`), STHs by `tree_size` — the same boundary
  rule as the monitor (successor signs from `effective_from_tree_size`).
  Receipt-role successions come from the `--successions` file, sth-role ones
  also from `embedded_succession` in the STH stream. Every succession is
  root-verified before its key is used for anything; unauthorized timeline
  segments report `KEY_CHANGED_UNAUTHORIZED`. Without a trust root (or
  without a genesis for the log) behavior is exactly the old single-key /
  `--sth-key` path. Cross-impl proof: `axr-verify-succession-test.js` runs
  both verifiers on the same rotated-log fixtures (10 assertions: control,
  happy path, boundary-violating signature, forged succession, post-rotation
  tamper) — JS and Python agree on accept AND reject.

- **`axr-key-succession` CLI** (`axr-key-succession.js`, added to `bin`).
  `build` creates a root-signed succession record (predecessor from a PEM file
  or a ready fingerprint) with self-verification before output; `verify`
  checks a record against a raw root public key OR a signed trust root (the
  trust root must verify itself first — no self-made anchors); `fingerprint`
  prints a key's fingerprint for rotation prep. 15 assertions incl. an
  end-to-end case: the CLI-built record embeds unchanged into the successor's
  first STH via the sidecar. `axr-succession.js` added to the package `files`
  list (anchor/monitor/verify now depend on it).

### Fixed

- **Fail-closed fork handling** (`buildKeyTimeline` + Python mirror): two (or
  more) root-signed successions targeting the same
  `effective_from_tree_size` no longer resolve "first-wins" — NO fork branch
  is authorized and the chain is poisoned from that boundary on, so a rotation
  built on either branch stays unauthorized too. Otherwise monitors/verifiers
  with different input order or partial visibility could accept different
  active keys for the same tree size — exactly the causality fork succession
  must close (Meridian cross-review finding). Cross-impl enforced: a forked
  receipt-succession makes both the JS and Python verifier reject the log.
- **Transitive timeline authorization** (`buildKeyTimeline`): after a broken
  chain link, properly-linked later successions no longer "self-heal" back to
  `authorized=true` — an attacker could otherwise enter via one broken jump
  and have every subsequent rotation appear authorized (NEXUS cross-review
  finding, fail-closed fix).
- **Deterministic succession chain hash** (monitor): records with equal
  `effective_from_tree_size` (forks) are now tie-broken by canonical hash, so
  two honest monitors seeing the same set in different order compute the same
  `succession_chain_hash` instead of raising a false split-view conflict
  (NEXUS cross-review finding).
- `axr-crossverify-test.js` now falls back from `python3` to `python` (verified
  Python 3.x) so the JS↔Python parity suite actually runs on Windows instead of
  skipping (the Store `python3` alias is a non-functional stub).

## [0.4.1] - 2026-06

Project build-out: closed a hidden-test integrity gap, implemented the feature it
covered, and added the governance/security layer expected of a published
cryptographic project. No change to the 0.2 wire format; all roots remain
byte-identical and the cross-implementation parity holds.

### Added

- **Incremental anchoring (MMR).** `core.mmrAppend` / `mmrRoot` / `mmrValid`, and
  an `anchor-state.json` cache in `runAnchor`: the sidecar appends only new leaves
  to a stored peak set instead of recomputing the whole Merkle tree each run
  (O(log n) per leaf). The MMR root is byte-identical to `merkleRootFromLeaves`
  for every n (proved n=1..40 in `axr-incremental-test.js`). A corrupt or stale
  cache fails an O(log n) structural check and triggers a from-scratch rebuild, so
  it can only cost time, never correctness. This implements the feature that
  `axr-incremental-test.js` was added for but which had no implementation.
- **Test auto-discovery.** `run-tests.js` now globs every `axr-*-test.js`, so a new
  test file is included in `npm test` and CI automatically — no hand-maintained
  list, and no test can silently escape CI (the root cause of the previously
  hidden, failing incremental test).
- **Governance and security.** `SECURITY.md` (responsible disclosure, supported
  versions, in/out-of-scope), `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  `.editorconfig`, GitHub issue/PR templates, and `dependabot.yml`
  (github-actions). License and zero-dependency badges in the README.
- **`AXR-SPEC-0.4.md`** — specification for the 0.4 layer (redactable, side-effect,
  trust root, key separation, incremental anchoring, strict mode), matching the
  0.2/0.3 spec bar.

### Fixed

- `axr-incremental-test.js` was committed red and excluded from CI (it tested an
  unimplemented MMR feature). It is now green and auto-discovered.

## [0.4.0] - 2026-06

Hardening pass. No change to the 0.2 wire format or to any existing receipt's
signature/leaf/chain hash; 0.1/0.2/0.3 logs continue to verify byte-for-byte.
Every item below ships with tests wired into `npm test` and CI.

### Added

- **Repository hygiene.** `LICENSE` (MIT), `package.json` with `npm test`,
  unified test runner (`run-tests.js`), and a GitHub Actions matrix
  (`.github/workflows/ci.yml`) running Node 18/20/22 x Python 3.10/3.11/3.12.
  Because the suite includes the JS<->Python cross-implementation parity test,
  a green CI run is the standing proof that both verifiers agree.
- **Trust root for side-effect attestation** (`axr-trust-root.js`,
  `core.buildTrustRoot` / `verifyTrustRoot` / `trustRootHasKey`). A root-signed,
  append-resistant allowlist binding provider names to permitted attestation
  keys. Closes the N1 "operator signs its own homework" gap: with a trust root
  supplied, an operator can no longer name its own key `google-calendar` and have
  the attestation count as `attested`. Verifier gains `--trust-root <json>`.
  Tested in `axr-trustroot-test.js`.
- **Key-role separation.** The verifier gains `--sth-key <pem>`, verifying Signed
  Tree Heads with a key distinct from the receipt-signing key. A compromised
  receipt key no longer lets an attacker forge tree heads, and vice versa. The
  anchoring sidecar already signs STHs with a dedicated key; this makes the
  verifier honor that separation. Tested in `axr-keysep-test.js`.
- **Strict mode.** Verifier `--strict` escalates "soft" signals — null
  `input_hash` (missing `__axr_input` marker), absent redactable detail, unknown
  reproducibility level — from notices to errors (exit 1). Intended as a CI gate.
  Tested in `axr-strict-test.js`.
- **OpenTimestamps loop closure.** `axr-anchor.js upgrade <anchors.jsonl>`
  re-queries the OTS calendars and confirms whether a committed root is now known
  (`GET /timestamp/<digest>`), promoting `ots_status` to `confirmed` and recording
  the upgrade response. Verifier gains `--online`, which performs the same
  calendar confirmation during check 12. The trust boundary is drawn explicitly:
  this proves calendar-level inclusion; final Bitcoin-block proof-of-work
  verification is delegated to the standard `ots verify` CLI over the recorded
  responses, by design (no Bitcoin SPV is reimplemented).

### Changed

- **Merkle internals are slice-free.** `_mth`, `merkleRoot`, `merkleRootFromLeaves`,
  `inclusionProof`, and `consistencyProof` now recurse over index ranges
  `[lo, hi)` instead of copying sub-arrays at every level (O(n log n) churn
  removed). Roots, proofs, and signatures are byte-identical — guaranteed by the
  canonical byte vectors and the JS<->Python cross-verify, both still green.

### Notes on limitations now narrowed

- **N1 (operator self-attestation):** narrowed by the trust root above when one is
  supplied. Without a trust root the prior behavior is unchanged (backward compat).
- **Operator-level key protection:** improved by key-role separation; full
  hardware/threshold key management remains out of scope and is still recommended
  for at-scale, customer-facing deployments.
- **Anchor loop:** the OTS calendar-level confirmation is now in code; Bitcoin PoW
  verification remains delegated to the `ots` CLI.

### Unchanged limitations (still honestly open)

- Uniform per-run timestamp (the generator runs once at workflow end).
- `$('NodeName')` cross-node access remains n8n-version-sensitive; the
  `__axr_input` marker convention mitigates but does not eliminate it.
- Self-declared `agent_id` (no central agent registry).
