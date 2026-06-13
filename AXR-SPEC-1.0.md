# Agent Execution Receipt (AXR) — Protocol Specification 1.0

**Status:** Stable. 1.0 is a **maturity declaration**, not a new protocol layer.
It consolidates 0.2–0.8 into one stable contract, proves the cross-version
compatibility claim with a single coherent test, completes the one promised
governance cleanup, and states the compatibility policy that 1.x guarantees.

The layer specifications (`AXR-SPEC-0.2.md` … `AXR-SPEC-0.8.md`) remain the
**normative** detail for each mechanism. This document is the **overview and the
1.x contract** — a map, a register, and the guarantees, not a rewrite.

---

## 1. Layer map

| Layer | Adds | Spec |
|---|---|---|
| 0.2 | Signed, chained, per-step execution receipts; canonicalization; cross-impl parity | 0.2 |
| 0.3 | RFC 6962 Merkle anchoring, Signed Tree Heads, the Monitor, generative steps | 0.3 |
| 0.4 | Redactable receipts, side-effect attestation, trust root, key-role separation, incremental anchoring, strict mode | 0.4 |
| 0.5 | Key succession (root-anchored rotation), embedded succession | 0.5 |
| 0.6 | Quorum root (M-of-N), root rotation/recovery, revocation, ceremony CLI | 0.6 |
| 0.7 | Control log (in-log anchored governance distribution) | 0.7 |
| 0.8 | Witness cosigning (preventive equivocation defence) | 0.8 |

Each layer is **additive and opt-in**: a deployment adopting none of 0.3–0.8
behaves exactly as 0.2. The cross-version compatibility matrix
(`axr-compat-matrix-test.js`) proves this as one test, anchored on a
byte-frozen legacy fixture (`fixtures/legacy-0.2.jsonl`).

## 2. Record-type register

`step`, `workflow`, `identity` (leaf, 0.2/0.3) · `sth` (0.3) · `anchor` (0.3) ·
`trust_root` (0.4; quorum 0.6) · `key_succession` (0.5) · `key_revocation`
(0.6) · `witness_set` (0.8). Governance records (`key_succession`,
`key_revocation`, `witness_set`) travel in the control log (0.7); an unknown
`record_type` on the control channel is **fail-closed**.

## 3. Violation / notice code register (the 1.x contract)

Violations: `BAD_SIGNATURE`, `ROOT_MISMATCH`, `NON_APPEND_ONLY`, `EQUIVOCATION`,
`TRUNCATION`, `LOG_ID_CHANGED`, `KEY_CHANGED`, `KEY_CHANGED_UNAUTHORIZED`,
`KEY_REVOKED`, `REVOCATION_UNAUTHORIZED`, `TRUST_ROOT_INVALID`,
`TRUST_ROOT_CHANGED`, `CONTROL_ROOT_MISMATCH`, `CONTROL_NON_APPEND_ONLY`,
`CONTROL_DOWNGRADE`, `CONTROL_WITHHELD`, `WITNESS_COSIGNATURE_INVALID`,
`WITNESS_SET_AMBIGUOUS`, `EMBEDDED_BYPASS`. Notices: `KEY_ROTATED_AUTHORIZED`,
`CONTROL_LAG`, `UNDER_WITNESSED` (default), `DEGRADED`, `ANCHOR_UNVERIFIED`.

These code **names** are part of the 1.x contract (see §6).

## 4. Volatile fields (post-signature, stripped from signature + chain hash)

`anchor_ref` (0.3), `redactable` detail (0.4), `witness_cosignatures` (0.8).
These are written/attached after the operator signs and are by definition
never part of any version's signature or chain hash — present-based stripping
in both implementations. This is what lets anchoring, redaction, and witness
cosigning be additive without breaking prior signatures (the cross-version
regression that `axr-legacy-anchor-test.js` and the compat matrix lock).

## 5. Integrity profile and stated non-guarantees (normative)

AXR proves a record was not altered, suppressed, or backdated after the fact —
**not** that it was honest when made. The honest limits, restated as the 1.0
integrity profile:

- **N1 — truth at signing.** Narrowed by side-effect attestation (0.4); not
  eliminated. A signed claim is not made true by its signature.
- **N2 — stolen key.** Succession/revocation (0.5/0.6) bound the damage in
  tree-position; they do not prevent a compromised key from signing.
- **N4 — monitor required.** The anti-tampering guarantees become *actual*
  only when an independent party runs the Monitor.
- **Witness preventiveness is conditional (0.8).** The witness gate is a
  genuine acceptance gate **only** under `--require-witnesses`; by default
  `UNDER_WITNESSED` is a compatibility notice. And it is preventive only while
  each witness keeps a **durable, non-rollbackable** state (witness host /
  state-store integrity is a trust assumption, not enforced in-protocol).
- **No emergency witness revocation.** Removing a compromised witness is a
  slow revoke (a new `witness_set`); fast in-protocol exclusion is **not**
  provided in 1.0. Tooling and docs MUST NOT claim otherwise.
- **No wall-clock validity in the trust path.** `tree_size` is the only clock.

## 6. Compatibility policy (what 1.x guarantees)

**Frozen for the life of 1.x** (breaking change only at 2.0):

- the **wire format** of every record type and the **canonicalization** (RFC
  8785/JCS), hash, and Ed25519 signature inputs — bit-for-bit;
- the **CLI exit-code contract** (0 valid, 1 violation, 2 usage/load) and the
  **violation/notice code names** in §3;
- **additive fields are permitted**; an unknown field on a non-trust-critical
  path is ignored, an unknown record type on the control channel is
  fail-closed.

**Explicitly NOT frozen in 1.0** (may change in a 1.x minor):

- the **JS module-export surface** of `axr-core` / `axr-succession` /
  `axr-control` etc. The internal programmatic API stabilizes in a later 1.x
  once real SDK/integration feedback exists; until then, depend on the CLI and
  the wire format, not on `require()` internals.
- The **Python verifier scope**: exit-code/verdict parity with the JS verifier
  is guaranteed; soft-notice output parity is not (the Python verifier is
  verdict-only by design).

**The one pre-declared cleanup:** since 1.0 the sidecar no longer writes
`embedded_succession` when a control log is in use (it refuses the
combination); standalone `--succession` (no control log) still writes it for
pure-0.5 deployments, and **reading/verifying** `embedded_succession` remains
for all existing logs. Where a control log is present, an embedded succession
absent from it is `EMBEDDED_BYPASS` (fail-closed). Migration: route key
governance through `axr-key-succession control add` (the control log).

## 7. Verifier checks (1.0 consolidated)

1–9 receipt/chain/evidence (0.2/0.3) · 10 inclusion proofs · 11 STH chain +
consistency · 12 anchor cross-check · 13 redactable · 14 side-effect · 15
rotation-spanning key timeline · 16 control-log commitment · 17 witness
cosignatures. Flags: `--strict`, `--sth-key`, `--trust-root`, `--online`,
`--successions`, `--revocations`, `--control`, `--require-witnesses`,
`--log-id`.

## 8. What 1.0 is not

Not a new mechanism. Deferred to post-1.0: emergency witness revocation,
partial control disclosure, multiple control namespaces, a frozen JS SDK
surface, wall-clock windows, HSM, true threshold cryptography. These are named
so their absence is a decision, not an oversight.
