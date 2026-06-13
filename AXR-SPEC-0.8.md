# Agent Execution Receipt (AXR) — Protocol Specification 0.8

**Status:** Preventive-equivocation layer (witness cosigning). Additive over
0.7. The 0.2 wire format remains frozen; `witness_cosignatures` is a volatile,
post-signature STH field (stripped from the operator signature and the chain
hash, exactly like `anchor_ref`), so 0.1–0.7 logs and signatures are
unaffected. Every 0.8 feature is opt-in: without a `witness_set` in the control
log, tooling behaves bit-for-bit as 0.7. `AXR-SPEC-0.3.md` … `AXR-SPEC-0.7.md`
remain in force.

---

## 1. What 0.8 adds over 0.7

0.5–0.7 closed the key lifecycle (issuance → rotation → revocation → recovery
→ distribution). The remaining gap is the *timing* of equivocation defence:
the 0.3 Monitor detects a split view **after the fact** (across views, over
time), leaving a window between publication and the first independent poll in
which an operator can show a divergent STH and a given consumer cannot tell it
is on the wrong branch.

0.8 makes the defence **preventive at the acceptance gate** with **witness
cosignatures** (the transparency-log pattern: CT 2.0, Sigsum). An STH is not
fully trusted until a threshold of independent witnesses have cosigned it.

**The honest framing (this is the real shape of the layer):** witness cosigning
is only preventive if the witness is **stateful** — it holds per-log consistency
state and **refuses to cosign an STH that is not an append-only continuation of
the last STH it cosigned**. A blind notary adds no protection. The threat-model
change is precise: 0.8 does **not** stop an operator from *producing* a split
view; it stops such a view from being *fully trusted* without a valid threshold
of cosignatures, and an honest stateful witness will not cosign the divergent
branch — so the operator cannot assemble the threshold.

## 2. witness_set — the witness circle (in the control log)

The witness circle lives in the **control log** (0.7) as a root/quorum-signed
governance record, **not** in the trust root. Rationale: the witness circle's
lifecycle is operational and frequent (an audit firm is replaced, a consortium
member leaves), whereas the trust root rotates ceremonially. Welding the two
would impose root-ceremony overhead and self-lockout risk on every witness
change. The control log is the existing anchored, append-only, withholding-proof
channel for exactly this kind of governance.

```
{
  "axr_version": "0.8",
  "record_type": "witness_set",
  "log_id": "...",
  "witnesses": [ { "name": "auditor", "public_key": "<PEM>" }, ... ],
  "witness_threshold": M,
  "effective_from_tree_size": N,
  "reason": "...",
  "issued_at": "...",
  <signature | signatures>      // single root key OR quorum (0.6), like key_succession
}
```

`witness_set` is a new control record type. Per the **forward-compat / version
gate** rule (P2): the control log is a trust-critical channel, so an unknown
`record_type` stays fail-closed; a new type is added to the recognized set
together with its consumer verification, so an older consumer never blindly
accepts governance it does not understand.

Multiple `witness_set` records form an **absolute policy timeline** (no
predecessor chaining — each is independently root-authorized): the active
policy at a `tree_size` is the latest `effective_from_tree_size <= tree_size`.
Two distinct sets at the same `effective_from_tree_size` are **ambiguous →
fail-closed** (that boundary has no active set).

## 3. Cosignatures on the STH

A witness cosigns the **full canonical STH body** minus `witness_cosignatures`
(so the operator signature and any embedded succession / control commitment are
all witness-covered). Cosignatures attach to the STH:

```
"witness_cosignatures": [ { "witness_fingerprint": "sha256:...", "signature": "<base64>" }, ... ]
```

sorted strictly ascending by `witness_fingerprint` (deterministic, like the 0.6
quorum signature set). Because they are added **after** the operator signs (the
operator publishes the STH, witnesses cosign, cosignatures are appended),
`witness_cosignatures` is stripped from both the operator `signablePart` and the
chain hash — adding them never breaks the operator signature or the STH chain.

## 4. Consumer behaviour

At each STH's `tree_size`, the consumer resolves the active witness set and
counts valid cosignatures from declared witnesses:

- **`WITNESS_COSIGNATURE_INVALID`** (always a violation): an undeclared signer,
  a duplicate, an unordered set, or an invalid signature. These are tampering,
  not policy.
- **`UNDER_WITNESSED`** (valid count < threshold): a **notice by default**, a
  **violation under `--require-witnesses`** (strict transparency mode). Default
  notice means a live, witness-less pilot is not broken on upgrade; requiring
  witnesses is an explicit opt-in.

Without a trust root or a `witness_set`, no witness check runs (0.7 behaviour).

An **ambiguous policy** (two distinct `witness_set` records at the same
`effective_from_tree_size`) is **fail-closed**: a `WITNESS_SET_AMBIGUOUS`
violation in every consumer, not a silent skip — otherwise two conflicting
root-signed sets could disable the gate for a range.

*Implementation note:* the Python verifier (`axr_verify.py`) is verdict-only
(it reports problems, not soft notices, per its documented scope). Default-mode
`UNDER_WITNESSED` is therefore silent in Python while the JS verifier prints a
notice; both produce the same exit code (0 by default, 1 under
`--require-witnesses`).

## 5. Witness operation (CLI + submission)

`axr-witness`:

- `sign <sth.jsonl|sth.json> <witness-priv.pem> --state <state.json> [--out f]`
  — cosigns the largest-`tree_size` STH **after the stateful append-only check**
  against `state.json` (per `log_id`): refuses a smaller `tree_size`
  (TRUNCATION) or a same-`tree_size`-different-`root` (EQUIVOCATION); idempotent
  on an identical STH; advances state on an extension. This refusal is what
  makes the witness preventive.
- `verify <sth-with-cosigs.json> <witness_set.json> <anchor>` — checks an STH's
  cosignatures against a witness set (validCount vs threshold; anomalies).

**Trust boundary (stated, Meridian review).** The preventive guarantee rests on
each witness using a **single, durable, non-rollbackable** state per log. The
witness host and its state storage are a trust assumption (like key custody):
rolling back, deleting, or running parallel state files under the same witness
key would let that witness cosign divergent branches. AXR fixes the cosignature
format and the witness's append-only obligation; the integrity of the witness's
state store is operational, not enforced by the protocol.

**Submission pattern (normative shape, transport is the operator's):** the
operator POSTs the published STH to each witness's endpoint; the witness runs
`sign` (applying its state) and returns the cosignature JSON; the operator
appends the collected cosignatures to the STH. The protocol fixes the
cosignature **format and verification**, not the network transport — exactly as
anchoring fixes the digest format, not the calendar protocol.

## 6. Witness revocation

Removing a witness is a **slow revoke**: issue a new `witness_set` (control log)
without that witness, effective from the next `tree_size`. Emergency exclusion
of a compromised witness without waiting for the next set was deferred here and
is now delivered in **1.1** as the `witness_revocation` record — see
`AXR-SPEC-1.1.md`.

## 7. embedded_succession — deprecated (P3)

The control log (0.7) is the primary governance channel. `embedded_succession`
(0.5, the sth-role succession riding in the successor's first STH) remains
supported for logs **without** a control log (removing it would break 0.5–0.7
compatibility), but is **deprecated** where a control log is present: the
sidecar emits a deprecation notice, and the field is slated for removal in
**1.0**. The same record may appear in both channels; the deterministic
canonicalization deduplicates it for free.

## 8. Codes and flags (0.8 summary)

New codes: `WITNESS_COSIGNATURE_INVALID` (violation, Critical in the OCSF
mapping), `UNDER_WITNESSED` (notice by default / violation under
`--require-witnesses`; Medium in OCSF). New flag: `--require-witnesses`
(monitor and both verifiers). All 0.7 codes and behaviours are unchanged.

## 9. Deferred (out of scope for 0.8)

- **Witness gossip / a built-in submission network** — the protocol fixes the
  cosignature format; the transport is operator/deployment choice.
- **Emergency witness revocation** (§6) — 0.9/1.0.
- **Partial control disclosure, multiple control namespaces** — still no driver
  (0.7 §7 deferral stands).
- **Wall-clock validity windows, HSM, true threshold crypto** — unchanged.

## 10. Compatibility summary

| Input | 0.8 tooling behavior |
|---|---|
| no witness_set, no cosignatures | 0.7 behaviour, bit-for-bit |
| witness_set present, STHs under threshold | `UNDER_WITNESSED` notice (violation only under `--require-witnesses`) |
| witness_set present, threshold met | STHs fully trusted at the acceptance gate |
| invalid/undeclared cosignature | `WITNESS_COSIGNATURE_INVALID` violation, always |

The 0.2 wire format, the RFC 6962 byte vectors, and all exit-code contracts are
unchanged.
