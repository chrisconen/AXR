# Changelog

All notable changes to AXR are documented here. The project follows the
spec-version scheme used throughout the codebase (0.2 stable core, 0.3 anchoring,
0.4 redactable / side-effect / trust-root, 0.5 key succession, 0.6
root-lifecycle hardening + SIEM export, 0.7 control log).

## [1.3.0] - 2026-06-13

Programmatic full-log verification in the SDK — additive, non-protocol.
Completes the SDK started in 1.2.

### Added

- **`axr.verify(opts)`** (`axr-sdk-verify.js`) — async full-log verification
  returning `{ ok, exitCode, problems, notices, output }`. It runs the
  **canonical verifier** (`axr-verify.js`) and derives the verdict from the
  **frozen exit-code contract** (0 valid / 1 invalid / 2 usage-IO), so the SDK
  verdict **can never diverge** from the CLI. `problems`/`notices` are
  best-effort lines parsed from the verifier report (human-readable; the text
  format is not frozen — the exit code is). `receipts` and `publicKey` (paths)
  are required; a spawn failure rejects.
- **`axr-sdk-verify-test.js`** (9 assertions): valid log → `ok:true`, tampered →
  `ok:false` with non-empty `problems`, **non-divergence** check (SDK `exitCode`
  equals the directly-run CLI exit code on the same inputs, valid and tampered),
  usage/IO error → `exitCode 2`, missing required opts → reject.
- `axr.verify` pinned in the SDK surface test; documented in `AXR-SDK.md`
  (the prior "not in the SDK yet" note is removed) and the README library section.

## [1.2.0] - 2026-06-13

Frozen public JavaScript SDK surface — additive (no wire-format, CLI, or
behaviour change). Fulfils the 1.0 commitment that the JS module export would
be frozen by the 1.x line. Doc: `AXR-SDK.md`.

### Added

- **`index.js` — the single documented SDK entry point** (`package.json` `main`).
  `require('axr')` returns a curated, stable surface: top-level conveniences
  (`version`, `canonicalize`, `sha256`, `sign`/`signReceipt`, `verifyReceipt`,
  `keyFingerprint`) plus namespaces (`core`, `governance`, `anchor`, `monitor`,
  `control`, `ocsf`, `report`, `generator`, `journalReceipts`, `webhook`). The
  full `core` surface is also spread at top level, so the pre-1.2 `main`
  (`axr-core.js`) contract is preserved — this change is non-breaking.
- **1.x JS stability policy** (`AXR-SDK.md`): the documented names/shapes are
  frozen for 1.x and may only grow additively; internal helpers reachable
  through a namespace but not documented are not frozen. Distinct from the
  `AXR-SPEC-1.0.md` wire/CLI freeze.
- **`axr-sdk-surface-test.js`** (86 assertions): pins every documented top-level
  name and namespace function (a rename/removal turns it red) and runs an
  end-to-end smoke test through the SDK (sign→verify, trust-root, witness_set +
  cosign + witness_revocation two-tier rule, control-log verify).

### Notes

- The CLI-only scripts `axr-verify.js` and `axr-trust-root.js` (which execute on
  require) are intentionally **not** part of the SDK; full-log verification stays
  the `bin/axr-verify` CLI, and programmatic integrity checking is
  `monitor.pollMonitor`. A unified `axr.verify()` wrapper is a candidate additive
  1.x extension.

## [1.1.0] - 2026-06-13

Emergency witness-revocation — additive over the frozen 1.0 contract (one new
control-log record type + one new violation code; no wire-format,
canonicalization, or CLI-exit-code change). A log with no `witness_revocation`
record verifies exactly as at 1.0. Spec: `AXR-SPEC-1.1.md`. Meridian + NEXUS
cross-review.

### Added

- **`witness_revocation` control-log record** (`axr-succession.js`:
  `buildWitnessRevocation` / `buildWitnessRevocationBody` /
  `buildQuorumWitnessRevocation` / `verifyWitnessRevocation`): a quorum/root-signed
  record that invalidates one witness fingerprint from a `revoked_at_tree_size`
  boundary — the structural mirror of the 0.6 `key_revocation`, for the 0.8
  witness circle. Closes the 0.8 §6 "emergency witness exclusion" deferral.
- **Two-tier semantics**, simpler than key-revocation: for an STH at `tree_size`
  T and a witness revoked at R, T < R → the cosignature still counts; T ≥ R →
  it does not count, and its presence on the STH raises **`WITNESS_REVOKED`**
  (always a violation; Critical in the OCSF mapping). `tree_size` is the
  unambiguous clock, so there is no "no-evidence" middle tier. The threshold is
  unchanged: a revocation that drops valid cosignatures below it surfaces as
  `UNDER_WITNESSED` (fail-closed, not a silent lowering of the bar).
- **Consumers**: monitor, JS verifier, and Python verifier (`axr_verify.py`)
  fold root-verified `witness_revocation` records into the witness timeline and
  apply the rule per STH; a forged/altered revocation in the control log is
  `CONTROL_ROOT_MISMATCH` (fail-closed, never anchored). `axr-control.js` accepts
  `witness_revocation` as a known control type; `axr-ocsf.js` maps
  `WITNESS_REVOKED` (severity 5).
- **CLI** (`axr-key-succession.js`): `revoke-witness` (single-key) and
  `body witness-revocation` (quorum ceremony), with `verify` / `assemble --verify`
  dispatch and self-verification before output.
- **Tests** (`axr-witness-revocation-test.js`, 34 assertions incl. Python
  cross-impl): record build/verify (single + quorum + tamper + foreign root),
  timeline + two-tier rule, monitor + both verifiers end-to-end, red-team forged
  revocation → `CONTROL_ROOT_MISMATCH`, foreign-`log_id` governance →
  `CONTROL_ROOT_MISMATCH`, multi-witness simultaneous revocation, and
  backward-compat (no revocation → unchanged).

### Review fixes (Meridian + NEXUS cross-review, both GO, no blocker)

- The offline JS/Python verifier now emits `CONTROL_ROOT_MISMATCH` (matching the
  monitor and the spec) when a `witness_set`/`witness_revocation` fails root
  verification, instead of a generic message — so code-based alerting agrees
  across all three consumers.
- The offline verifier now **filters witness governance by `log_id`** (as the
  monitor already did): a same-root-signed but foreign-log `witness_set`/
  `witness_revocation` is rejected `CONTROL_ROOT_MISMATCH` and cannot enter the
  witness timeline (closes a threshold-weakening trust-boundary gap).

## [1.0.2] - 2026-06-13

Additive tooling/robustness on top of the frozen 1.0 contract (no protocol,
wire-format, or canonicalization change).

### Changed

- **Dev-log snapshot now carries genuinely process-independent witness
  cosignatures.** The two cosignatures in `devlog/sth.jsonl` are no longer
  produced inside the orchestrator process: the real reviewer agents each
  generated their own Ed25519 key and cosigned the STH in their own separate
  process (Meridian via Codex/GPT-5.5 → `devlog/meridian.pubkey.pem`,
  `sha256:08d5e6dc…`; NEXUS via Gemini → `devlog/nexus.pubkey.pem`,
  `sha256:c73214af…`). The orchestrator never saw either private key — it only
  assembled the finished cosignatures. `devlog/README.md` updated: this is
  genuine *process-level* independence; the only remaining gap to full
  zero-trust is same-machine custody (production = separate security zones).
- `buildDevlog()` gained `opts.witnesses` (externally supplied witness public
  keys → used in the `witness_set`, internal witness keygen skipped) and
  `opts.skipCosign` (the orchestrator does not cosign — external agents produce
  the cosignatures), enabling the genuine-independence flow above.

### Added

- **`axr-witness.js sign` state-write fallback for restricted filesystems.**
  The atomic `tmp → rename` state update now falls back to a direct write when
  `rename` throws (`EPERM` under sandboxes, file locks, AV, network FS), and an
  `AXR_WITNESS_NO_ATOMIC=1` escape hatch forces the direct path on known-flaky
  filesystems. The cosignature (a deterministic, stateless signature) is never
  blocked by a state-persistence quirk; the stateful equivocation guards still
  apply on the fallback path. New CLI test cases cover both.

## [1.0.1] - 2026-06-13

Additive tooling on top of the frozen 1.0 contract (no protocol change): AXR
demonstrated on real, non-fixture data — its own development journal.

### Added

- **Dogfooding: a verifiable AXR log of AXR's own development**
  (`axr-journal-receipts.js` + `axr-dogfood.js`; `npm run dogfood`; frozen
  snapshot in `devlog/`). The three-AI workbench journal (`agents/journal.jsonl`)
  becomes signed journal-entry receipts, anchored into an STH, and
  witness-cosigned by the two reviewer agents (Meridian, NEXUS) — the
  cross-review that caught eleven findings during 0.5–1.0, now expressed as
  literal witness cosignatures. Runs the full 1.0 stack (anchor → monitor →
  JS + Python verifier, `--require-witnesses`) on real data. 10 assertions
  incl. determinism, content-binding (a journal edit breaks the receipt), and
  the committed frozen snapshot verifying under both verifiers.
- **Honest framing throughout** (per Meridian/NEXUS review): receipts prove the
  journal is unaltered since signing, **not** that entries were true when
  written (N1); the local snapshot **simulates** independent witness custody
  (production runs witnesses in separate security zones); framed as a
  machine-generated audit trail / a tool in the human auditor's hand, not "AI
  self-governance". No private keys committed (only public keys + the signed
  artifact). See `devlog/README.md`.

## [1.0.0] - 2026-06-13

Maturity declaration — not a new layer. 1.0 consolidates 0.2–0.8 into one
stable contract, proves the cross-version compatibility claim, completes the
one promised governance cleanup, and states the 1.x compatibility policy.
Spec: `AXR-SPEC-1.0.md` (overview + contract); the 0.2–0.8 layer specs remain
the normative detail. Scope/decision trail: `AXR-0.1-...`/`AXR-1.0-SCOPE.md`,
synthesized from Meridian (readiness/threat-model) and NEXUS (value/adoption)
reviews; Meridian gated approval on the integrity profile being normatively
fixed and test-covered — now done.

### Added

- **Cross-version compatibility matrix** (`axr-compat-matrix-test.js`, 13
  assertions) anchored on a **byte-frozen legacy fixture**
  (`fixtures/legacy-0.2.jsonl`, committed, never regenerated): every layer
  opt-out yields prior behaviour, the frozen 0.2 log verifies (and a tamper
  rejects) under both 0.8 verifiers, a full 0.8 stack passes anchor → monitor
  → JS + Python verifier, and the volatile fields are additive. A live
  regression lock on the "frozen wire format" claim.
- **`AXR-SPEC-1.0.md`** — layer map, record-type and code registers, volatile-
  field list, the normative integrity profile (N1/N2/N4 + the conditional
  witness preventiveness + no-emergency-revocation, stated as limits), the
  consolidated verifier checks 1–17, and the **1.x compatibility policy**:
  wire format / canonicalization / hash / signature inputs / CLI exit codes /
  code names are frozen for 1.x (breaking only at 2.0); the JS module-export
  surface is explicitly **not** frozen in 1.0 (stabilizes later in 1.x); the
  Python verifier guarantees verdict parity, not notice parity.

### Changed (governance cleanup)

- **`embedded_succession` writer removed where a control log is in use.** The
  sidecar refuses `--succession` together with `--control` (fail-fast);
  standalone `--succession` (no control log) still writes it for pure-0.5
  deployments, and reading/verifying it remains for all existing logs. Where a
  control log is present, an embedded succession absent from it is the new
  `EMBEDDED_BYPASS` violation (monitor + both verifiers) — closing the
  governance-channel-bypass residue Meridian flagged. Migration: route key
  governance through `axr-key-succession control add`.

## [0.8.0] - 2026-06-13

Preventive-equivocation layer: STH witness cosignatures make equivocation
defence preventive at the acceptance gate, not just detect-after-the-fact.
Spec: `AXR-SPEC-0.8.md`; scope decision trail: `AXR-0.8-SCOPE.md`
(Meridian/NEXUS review). The 0.2 wire format is untouched — `witness_cosignatures`
is a volatile post-signature STH field (stripped like `anchor_ref`). Opt-in;
without a `witness_set` the tooling behaves bit-for-bit as 0.7.

### Added

- **Witness cosigning core** (`axr-succession.js`). `witness_set` (root/quorum-
  signed, declares the witness circle + threshold + `effective_from_tree_size`,
  carried in the control log — operational lifecycle, not the trust root);
  `buildWitnessTimeline`/`witnessAt` (absolute root-authorized policy records;
  same `effective_from` = ambiguous, fail-closed); `cosignWitness`/
  `assembleWitnessCosignatures` (deterministic fingerprint order);
  `verifyWitnessCosignatures` (strict fail-closed on undeclared/duplicate/
  unordered/invalid; under-threshold is a separate count, not an anomaly).
- **Volatile `witness_cosignatures`** (core + Python): stripped from
  `signablePart` and `chainHash` present-based, so witnesses cosign after the
  operator signs without breaking the operator signature or the STH chain.
  `witness_set` added to the control-log record-type allowlist (forward-compat
  version gate; unknown type stays fail-closed).
- **`axr-witness` CLI** (in `bin`). Stateful `sign` — refuses a non-append-only
  STH (TRUNCATION on smaller tree_size, EQUIVOCATION on same size + different
  root, idempotent on identical, extension on larger): the invariant that makes
  witnessing preventive rather than a blind notary. Plus `verify` and a
  normative submission pattern in the spec.
- **Consumer gating** (monitor + both verifiers, check 17). Every STH is gated
  against the active witness set: `WITNESS_COSIGNATURE_INVALID` (always a
  violation), `UNDER_WITNESSED` (notice by default, violation under
  `--require-witnesses` — strict transparency is opt-in so a live witness-less
  pilot is not broken). OCSF mapping extended.
- 42 new assertions across three suites (witness core, CLI, end-to-end) with
  Python cross-impl agreement on accept AND reject.

### Deprecated

- `embedded_succession` (0.5) where a control log is present — the control log
  is the primary governance channel; the sidecar emits a deprecation notice,
  removal slated for 1.0.

## [0.7.1] - 2026-06-13

Tooling release on top of 0.7 — two operator-facing tools, **no protocol or
wire-format change** (the 0.8 number is reserved for the next protocol layer).
Both were built as separate tracks and adversarially reviewed
(NEXUS/Meridian); the rollout preflight was hardened to fail closed on
rotated/partial logs.

### Added

- **Production rollout tooling** (`axr-rollout.js`, in `bin` as `axr-rollout`;
  runbook `ROLLOUT.md`). Brings a running 0.2–0.4 pilot (one operator key,
  TOFU) onto the 0.5–0.7 root-anchored model without losing the existing log.
  `bootstrap` builds a trust root (single or quorum) from the keys already in
  use — the genesis IS the current signer, so existing STHs stay valid (no
  re-signing/re-anchoring). `preflight` is a GO/NO-GO readiness check that
  targets the self-lockout risk NEXUS flagged: its key finding `GENESIS_SIGNS`
  /`GENESIS_MISMATCH` confirms the declared genesis actually signs the earliest
  STH; it also flags an invalid trust root, a committing STH with no control
  log shipped, plus warnings for local-only anchoring (N3), no independent
  monitor (N4) and a degenerate quorum threshold — each with a remediation
  hint, and it embeds the authoritative `axr-verify.js` verdict. The runbook
  documents the migration order and the common self-lockout traps. 17
  assertions incl. the GENESIS_MISMATCH self-lockout case. Separate track (not
  protocol scope) — the adoption-safety net.
- **Compliance Report Generator** (`axr-report.js`, in `bin` as `axr-report`).
  Produces a self-contained, human-auditable HTML (or JSON) report from an AXR
  log: log overview, signature/anchoring integrity, the key-governance
  timeline (genesis + successions + revocations, active key per role,
  authorized/revoked flags), control-log commitment summary, privacy/
  side-effect counts, and an EU AI Act Art.12 / GDPR control mapping drawn
  from COMPLIANCE.md (with the honest caveats). Honest framing per the project
  doctrine: the report is a *view* over the verifier's verdict — the big
  PASS/FAIL banner is the exit code of `axr-verify.js` run with the same
  flags, faithfully reported; the report asserts nothing it did not check and
  states the N1/N2/N4 limits explicitly. Reproducible (same inputs → same
  report, generation timestamp aside). 18 assertions incl. a cross-check that
  the report verdict matches the verifier on both a valid log and a tampered
  one. A separate track (not protocol scope) — the NEXUS-identified "what an
  auditor asks for first."

## [0.7.0] - 2026-06-13

Governance-distribution layer: the control log closes the withholding and
revocation-absorption gaps left by 0.6's out-of-band distribution. Spec:
`AXR-SPEC-0.7.md`; scope decision trail: `AXR-0.7-SCOPE.md` (Meridian/NEXUS
review). The 0.2 wire format is untouched — the control log is a separate
sidecar file, the commitment two additive STH fields. Every feature is
opt-in; without a control log the tooling behaves bit-for-bit as 0.6.

### Added

- **Control log core** (`axr-control.js`). `controlRoot` (RFC 6962 over
  governance records, reusing the receipt-tree machinery — the empty log has
  a real root), `verifyControlRecord`/`verifyControlLog` (full root/quorum
  crypto verification + log_id guard + record-type allowlist),
  `checkSthCommitment` (control_root_hash + control_size against the actual
  log, withheld detection), `checkControlConsistency` (append-only over the
  control tree). Anchors are PEM, trust root or chain.
- **Sidecar commitment** (`axr-anchor --control --control-trust-root`). The
  STH signed body commits `control_root_hash` + `control_size`; per the
  Meridian condition the sidecar fully verifies every control record before
  committing and throws on any invalid record (no DoS/self-lockout surface).
  Empty log commits `control_size=0`. Without `--control` the STH is unchanged.
- **Monitor consumption** (`--control`). Governance records feed the same
  verified, deduplicated pools; STH commitments are checked against the log.
  New codes: `CONTROL_ROOT_MISMATCH`, `CONTROL_NON_APPEND_ONLY`,
  `CONTROL_DOWNGRADE`, and withholding via the decided escalation —
  `CONTROL_LAG` notice (one poll cycle of replication tolerance) then
  `CONTROL_WITHHELD` violation; the journal pins max control_size + root.
- **Verifier consumption** (`--control`, JS + Python). Check 16: every
  committing STH validated against the control log; offline so withholding is
  immediately fail-closed. The Python verifier mirrors `control_root`,
  `check_sth_commitment` and `check_control_consistency`.
- **Control CLI** (`axr-key-succession control add|verify|status`). `add`
  appends only after full verification; `verify` is an offline lint; `status`
  resolves the active key per role at a tree size.
- OCSF mapping extended with the four control codes. 55 new assertions across
  five suites (control core, sidecar, monitor, cross-impl verifier, CLI), with
  JS↔Python agreement on accept AND reject.

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
