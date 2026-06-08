# Changelog

All notable changes to AXR are documented here. The project follows the
spec-version scheme used throughout the codebase (0.2 stable core, 0.3 anchoring,
0.4 redactable / side-effect / trust-root).

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
