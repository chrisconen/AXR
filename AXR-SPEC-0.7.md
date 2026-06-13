# Agent Execution Receipt (AXR) — Protocol Specification 0.7

**Status:** Governance-distribution layer. Additive over 0.6. The 0.2 wire
format remains frozen — the receipt log, `LEAF_TYPES` and the receipt Merkle
tree are untouched. Every 0.7 feature is opt-in: a deployment without a
control log keeps the 0.6 behavior bit-for-bit. `AXR-SPEC-0.3.md` …
`AXR-SPEC-0.6.md` remain in force.

---

## 1. What 0.7 adds over 0.6

0.6 closed the root key's lifecycle, but receipt-role successions and all
revocations still travelled **out-of-band** (`--successions`,
`--revocations`). Two gaps remained:

1. **Withholding** — the operator could show different consumers different
   governance sets; nothing anchored *which* set was in force at a given tree
   size.
2. **Revocation absorption** — an inconvenient revocation could simply be
   "lost" in distribution, undetectably.

0.7 closes both with a **control log**: governance records live in an
append-only `control.jsonl`, and the STH signed body **commits** to it.

## 2. Control log and commitment

### 2.1 Records and tree

`control.jsonl` is an append-only JSONL of governance records
(`key_succession` of any role, `key_revocation`). Record authority is
unchanged — the root/quorum signature (0.5/0.6). The control log is purely the
**distribution channel**; it carries no new authority.

The control tree is the RFC 6962 Merkle tree over the records (the same
machinery as the receipt tree; a record's leaf is its full canonical bytes).
The empty control log has a real root (`merkleRootFromLeaves([])`), so the
"no governance event yet" claim is itself provable.

### 2.2 STH commitment

A control-aware STH carries two additive signed-body fields:

```
"control_root_hash": "sha256:...",   // RFC 6962 root over the first control_size records
"control_size":      N
```

Both are inside the signed body, so the STH signature, the STH chain hash and
the external anchor all cover them. The committed set is therefore fixed at
every tree size, and withholding or absorption becomes loud.

### 2.3 Sidecar duty (fail-closed at the source)

`axr-anchor --control <log> --control-trust-root <anchor>`: before committing,
the sidecar **fully cryptographically verifies every control record** (root/
quorum signature, `log_id`, record-type allowlist) and throws on any invalid
record. Invalid governance material must never be anchored — anchoring it would
force every consumer into fail-closed (a DoS / self-lockout surface). The
`--control-trust-root` is therefore mandatory alongside `--control`.

## 3. Consumer rules

### 3.1 Commitment and append-only

A consumer with the control log checks, for every committing STH, that
`control_root_hash` equals the root over the first `control_size` records
(`CONTROL_ROOT_MISMATCH` otherwise), and that the committed set only grows
across committing STHs (`CONTROL_NON_APPEND_ONLY` on shrink/rewrite, via the
consistency-proof machinery over the control tree). Governance records from
the control log feed the same root-verified, deduplicated timeline pools as
the out-of-band sources — so a receipt-role succession distributed only via
the control log authorizes rotation-spanning receipts with no `--successions`
flag.

### 3.2 Downgrade

If the largest-tree-size STH drops a commitment that a smaller one made,
that is `CONTROL_DOWNGRADE` — a violation. Otherwise an operator could hide a
revocation by simply ceasing to commit. There is no silent downgrade; a
genuine migration is an explicit new log/genesis, not a dropped field.

### 3.3 Withholding — monitor vs verifier

- **Monitor** (online, polls over time): a first poll where the published
  control log is shorter than the committed `control_size` is `CONTROL_LAG`
  (a notice, with a journal marker) — tolerating one poll cycle of
  asynchronous replication lag. A repeat on the next poll is
  `CONTROL_WITHHELD` (a violation). No wall-clock grace enters the trust
  path; the tolerance is exactly one cycle. The journal also pins the largest
  seen `control_size` + root, so a cross-poll shrink is
  `CONTROL_NON_APPEND_ONLY`.
- **Verifier** (offline, files in hand): no lag is possible, so a short or
  missing control log is immediately `CONTROL_WITHHELD`, fail-closed.

### 3.4 Identity and epoch (the named risk)

A control log is bound to its `log_id` (every record carries it; the
commitment lives in that log's STHs). Root rotation does **not** reset it:
records re-issued under the new quorum append, the old ones remain as history.
The monitor's genesis pin (0.6) anchors *which* trust-root chain governs, so
two parties cannot diverge on the control history of the same receipt log
without one of them seeing a `TRUST_ROOT_CHANGED` or
`CONTROL_NON_APPEND_ONLY`. An unknown `record_type` in the control log is a
violation (fail-closed; a version gate is future work, when a new type
exists).

## 4. Relationship to embedded_succession (0.5)

`embedded_succession` (the sth-role succession riding in the successor's first
STH) remains the rotation-announcement channel for logs **without** a control
log — removing it would break 0.5/0.6 compatibility. Where a control log is
present, it is the **primary** governance channel; the same record may appear
in both (deduplicated for free by the deterministic canonicalization), and
`embedded_succession` may be retired in a later major version.

## 5. CLI

`axr-key-succession control`:

- `add <control.jsonl> <record.json> --trust-root <anchor> [--log-id <id>]` —
  appends a record only after full verification (self-lockout protection: an
  invalid record never enters the log).
- `verify <control.jsonl> <anchor> [--log-id <id>]` — offline lint of an
  existing control log; prints the control root.
- `status <control.jsonl> <trust-root> --log-id <id> [--at <tree_size>]` —
  the active key per role at a given tree size (the append-only event log
  resolved to current state), flagging unauthorized or revoked keys.

Anchors are PEM, trust root, or chain everywhere (`status` needs a
genesis-bearing trust root).

## 6. Codes and flags (0.7 summary)

New codes (all violations): `CONTROL_WITHHELD`, `CONTROL_NON_APPEND_ONLY`,
`CONTROL_DOWNGRADE` (Critical in the OCSF mapping), `CONTROL_ROOT_MISMATCH`
(High); `CONTROL_LAG` is a notice. New flags: `--control <jsonl>` (monitor and
both verifiers), `--control` + `--control-trust-root` (sidecar). All 0.6 codes
and behaviors are unchanged.

## 7. Deferred (out of scope for 0.7)

- **Partial control disclosure** (inclusion proofs over the control tree) —
  the control log is small; the full set is the normal path. The Merkle root
  leaves the proof-based path open if it ever grows large.
- **Multiple control namespaces per log** — single namespace per `log_id` for
  now; cross-tree binding would be the trigger to add it.
- **Version gate for new control record types** — added when a second schema
  version exists.
- **Wall-clock validity windows; HSM; true threshold crypto** — unchanged
  from prior specs.

## 8. Compatibility summary

| Input | 0.7 tooling behavior |
|---|---|
| no committing STH, no control log | 0.6 behavior, bit-for-bit |
| committing STHs but control log not supplied | `CONTROL_WITHHELD`, fail-closed — a commitment cannot be silently skipped |
| control log + committing STHs | full commitment + append-only + withholding checks |
| empty control log committed | `control_size=0`, the empty-tree root — "no governance event" proven |

The "no committing STH" row is the precise backward-compat case: a 0.3–0.6
log (no `control_root_hash` anywhere) runs no control checks. The moment any
STH commits, the commitment is binding — withholding the control log is a
violation, not an opt-out.

The 0.2 wire format, the RFC 6962 byte vectors, and all exit-code contracts
are unchanged.
