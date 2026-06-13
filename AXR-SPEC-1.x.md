# Agent Execution Receipt (AXR) — 1.x living overview (current map)

**Status:** the **current** map, register, and guarantees for the 1.x line.
`AXR-SPEC-1.0.md` is the frozen 1.0 *snapshot*; this document **supersedes its
registers** (§2 record types, §3 codes, §6 compat policy) with the 1.1–1.5
additions, and is kept current as 1.x evolves. The per-layer specs
(`AXR-SPEC-0.2.md` … `0.8`, `1.0`, `1.1`, `1.4`, `1.5`) remain the normative
detail; this is the overview an adopter or auditor reads first.

Everything added after 1.0 is **additive**: no wire format, canonicalization,
CLI exit code, or pre-1.0 behaviour has changed. A deployment that uses none of
the 1.1–1.5 features behaves exactly as 1.0 (and 1.0 as 0.2).

---

## 1. Layer map

| Layer | Adds | Spec |
|---|---|---|
| 0.2 | Signed, chained, per-step execution receipts; canonicalization; cross-impl parity | 0.2 |
| 0.3 | RFC 6962 Merkle anchoring, Signed Tree Heads, the Monitor, generative steps | 0.3 |
| 0.4 | Redactable receipts, side-effect attestation, trust root, key-role separation, incremental anchoring, strict mode | 0.4 |
| 0.5 | Key succession (root-anchored rotation), embedded succession | 0.5 |
| 0.6 | Quorum root (M-of-N), root rotation/recovery, key revocation, ceremony CLI | 0.6 |
| 0.7 | Control log (in-log anchored governance distribution) | 0.7 |
| 0.8 | Witness cosigning (preventive equivocation defence) | 0.8 |
| 1.0 | Maturity consolidation, cross-version compat proof, governance cleanup | 1.0 |
| 1.1 | **Emergency witness revocation** (`witness_revocation`, permanent) | 1.1 |
| 1.2 | **Frozen public JS SDK surface** (`require('axr')`) | — (SDK) |
| 1.3 | **Programmatic full-log verification** (`axr.verify()`) | — (SDK) |
| 1.4 | **Temporary witness suspension** (`witness_suspension`, auto-expiring) | 1.4 |
| 1.5 | **Partial control-disclosure** (off-wire inclusion proof on the control tree) | 1.5 |

The witness lifecycle is now complete: **slow revoke** (a new `witness_set`,
0.8) → **emergency revoke** (`witness_revocation`, 1.1, permanent) → **temporary
suspend** (`witness_suspension`, 1.4, auto-expiring `[from, until)`).

## 2. Record-type register (current)

`step`, `workflow`, `identity` (leaf, 0.2/0.3) · `sth` (0.3) · `anchor` (0.3) ·
`trust_root` (0.4; quorum 0.6) · `key_succession` (0.5) · `key_revocation`
(0.6) · `witness_set` (0.8) · **`witness_revocation` (1.1)** · **`witness_suspension`
(1.4)**. The governance records (`key_succession`, `key_revocation`,
`witness_set`, `witness_revocation`, `witness_suspension`) travel in the control
log (0.7); an unknown `record_type` on the control channel is **fail-closed**.

A **control disclosure** (1.5) is **not** a record type — it is an off-wire
proof object `{ record, leaf_index, control_size, inclusion_proof,
control_root_hash }` a holder produces on request; it never appears in a log.

## 3. Violation / notice code register (the 1.x contract)

Violations: `BAD_SIGNATURE`, `ROOT_MISMATCH`, `NON_APPEND_ONLY`, `EQUIVOCATION`,
`TRUNCATION`, `LOG_ID_CHANGED`, `KEY_CHANGED`, `KEY_CHANGED_UNAUTHORIZED`,
`KEY_REVOKED`, `REVOCATION_UNAUTHORIZED`, `TRUST_ROOT_INVALID`,
`TRUST_ROOT_CHANGED`, `CONTROL_ROOT_MISMATCH`, `CONTROL_NON_APPEND_ONLY`,
`CONTROL_DOWNGRADE`, `CONTROL_WITHHELD`, `WITNESS_COSIGNATURE_INVALID`,
`WITNESS_SET_AMBIGUOUS`, **`WITNESS_REVOKED` (1.1)**, `EMBEDDED_BYPASS`.
Notices: `KEY_ROTATED_AUTHORIZED`, `CONTROL_LAG`, `UNDER_WITNESSED` (default),
**`WITNESS_SUSPENDED` (1.4)**, `DEGRADED`, `ANCHOR_UNVERIFIED`.

These code **names** are part of the 1.x contract (§6). `WITNESS_REVOKED` is a
violation (a revoked witness's cosignature past its boundary); `WITNESS_SUSPENDED`
is a benign notice (a temporarily-suspended witness inside its window). The OCSF
mapping (`axr-ocsf.js`) assigns `WITNESS_REVOKED` severity 5 and
`WITNESS_SUSPENDED` severity 1.

## 4. Volatile fields (post-signature, stripped from signature + chain hash)

`anchor_ref` (0.3), `redactable` detail (0.4), `witness_cosignatures` (0.8).
Unchanged since 1.0 — present-based stripping in both implementations; this is
what keeps anchoring, redaction, and witness cosigning additive.

## 5. Witness lifecycle (0.8 → 1.4)

For an STH at `tree_size = T` and a witness `F`:

- **Cosigning (0.8):** `F` in the active `witness_set` with a valid cosignature
  counts toward the threshold. Anomalies (undeclared/duplicate/unordered/invalid)
  → `WITNESS_COSIGNATURE_INVALID`; below threshold → `UNDER_WITNESSED`.
- **Revoked (1.1)** at `R`: for `T ≥ R`, `F` does not count and its presence is
  `WITNESS_REVOKED` (violation). Permanent.
- **Suspended (1.4)** over `[from, until)`: for `from ≤ T < until`, `F` does not
  count and its presence is `WITNESS_SUSPENDED` (benign notice); from `until` it
  counts again automatically. Temporary.
- **Precedence:** revocation > suspension (a compromise signal is never
  downgraded). A suspended cosignature is classified benign only if it is a
  *declared* witness with a *valid* signature — otherwise it is
  `WITNESS_COSIGNATURE_INVALID`.
- **Threshold never shrinks:** revocation/suspension withhold a contribution;
  if that drops the valid count below threshold the STH is `UNDER_WITNESSED`
  (and recovers automatically when a suspension expires).

## 6. SDK (1.2 / 1.3)

`require('axr')` (`index.js`) is the **frozen public library surface**: top-level
conveniences (`canonicalize`, `sha256`, `sign`/`signReceipt`, `verifyReceipt`,
`keyFingerprint`, `verify`, `version`) and namespaces (`core`, `governance`,
`anchor`, `monitor`, `control`, `ocsf`, `report`, `generator`, `journalReceipts`,
`webhook`). `axr.verify(opts)` (1.3, async) runs the canonical verifier and
derives its verdict from the frozen exit-code contract, so it **cannot diverge**
from the CLI. The surface is pinned by `axr-sdk-surface-test.js`. Full detail:
`AXR-SDK.md`.

## 7. Partial control-disclosure (1.5)

`control.buildControlDisclosure(records, index)` /
`control.verifyControlDisclosure(disclosure, expectedRoot?)` let a holder prove
that **one** governance record is committed in the control tree (RFC 6962
inclusion against the STH `control_root_hash`) without revealing the other
records. The auditor chain (`control verify-inclusion`, `--key` required): STH
signature → disclosure root **and size** equal the STH's signed commitment +
inclusion verifies → (optional) record is root-authorized. Off-wire; the Python
verifier mirrors it (`verify_control_disclosure`). Detail: `AXR-SPEC-1.5.md`.

## 8. Integrity profile and stated non-guarantees (normative)

AXR proves a record was not altered, suppressed, or backdated after the fact —
**not** that it was honest when made.

- **N1 — truth at signing.** Narrowed by side-effect attestation (0.4); not
  eliminated.
- **N2 — stolen key.** Succession/revocation (0.5/0.6) and the witness lifecycle
  (0.8–1.4) bound the damage in tree-position; they do not prevent a compromised
  key from signing.
- **N4 — monitor required.** The anti-tampering guarantees are *actual* only
  when an independent party runs the Monitor.
- **Witness preventiveness is conditional (0.8).** A genuine acceptance gate
  **only** under `--require-witnesses`; preventive only while each witness keeps
  **durable, non-rollbackable** state (a host/state-store trust assumption).
- **Witness governance is root/quorum authority.** Revocation and suspension are
  root/quorum-signed; there is **no** witness self-revocation/self-suspension.
- **No wall-clock validity in the trust path.** `tree_size` is the only clock —
  including suspension windows.

## 9. Compatibility policy (what 1.x guarantees)

**Frozen for the life of 1.x** (breaking change only at 2.0):

- the **wire format** of every record type and the **canonicalization** (RFC
  8785/JCS), hash, and Ed25519 signature inputs — bit-for-bit;
- the **CLI exit-code contract** (0 valid, 1 violation, 2 usage/load) and the
  **violation/notice code names** in §3;
- since **1.2**, the **public JS SDK surface** documented in `AXR-SDK.md`
  (`require('axr')`) — frozen for 1.x, additive growth only. *(This supersedes
  the 1.0 snapshot, which listed the JS surface as not-yet-frozen.)*
- **additive fields are permitted**; an unknown field on a non-trust-critical
  path is ignored, an unknown record type on the control channel is fail-closed.

**Parity guarantee (scoped precisely).** The Python verifier is the cross-impl
proof of the **cryptographic core + governance**: signatures, all hash chains,
`chain_root`/`step_chain`, RFC 6962 inclusion + consistency, the STH chain, the
rotation-spanning key timeline + revocation, the control-log commitment, the full
witness lifecycle (cosigning, `witness_revocation` 1.1, `witness_suspension` 1.4),
and control disclosure (1.5). Verdict parity on these is guaranteed and
test-locked. **Not** part of the parity guarantee: the niche 0.3/0.4 semantic
checks — redactable-commitment integrity, side-effect attestation, generative
well-formedness, evidence-graph integrity, and the online anchor cross-check —
which are **JS-only by design** (`axr-verify.js` is their reference;
`axr_verify.py` exits on core validity and says so in its header). Soft-notice
*output* parity is also not guaranteed (Python is verdict-only). A log that JS
rejects solely on a JS-only niche check may therefore exit 0 in Python — the
cross-impl claim is about the trust-critical core, not every semantic rule.

## 10. Verifier checks (current)

1–9 receipt/chain/evidence (0.2/0.3) · 10 inclusion proofs · 11 STH chain +
consistency · 12 anchor cross-check · 13 redactable · 14 side-effect · 15
rotation-spanning key timeline · 16 control-log commitment · 17 witness
cosignatures (incl. revocation 1.1 + suspension 1.4). Flags: `--strict`,
`--sth-key`, `--trust-root`, `--online`, `--successions`, `--revocations`,
`--control`, `--require-witnesses`, `--log-id`. Programmatic: `axr.verify()`;
partial disclosure: `control verify-inclusion`.

## 11. Still deferred (named so their absence is a decision)

Delivered since the 1.0 list: emergency witness revocation (1.1), partial
control disclosure (1.5), a frozen JS SDK surface (1.2). **Still open:** multiple
control namespaces, wall-clock windows, HSM-grade key storage, true threshold
cryptography, witness self-revocation/self-suspension, and — operational, not
protocol — switching the production anchor backend to OpenTimestamps once the
cadence is stable, and exercising the higher layers on the live pilot.
