# AXR 1.5 — Partial control-disclosure

Status: **additive over the frozen 1.0 contract.** 1.5 adds an **off-wire
verification aid** — a single-record inclusion proof against the control tree.
It introduces **no** new record type, no new wire field, no version gate, and no
consumer code: a disclosure is something a holder *produces on request*, not
part of the log. Nothing about how logs are written or verified changes.

## 1. The gap

The 0.7 control log commits the governance records into each STH:
`control_root_hash` (RFC 6962 Merkle root over the first `control_size` control
records) + `control_size`, inside the operator-signed STH body. Until now, a
consumer that wanted to check that commitment had to be given the **entire**
control log. That is fine for a monitor or a full verifier, but it forces an
operator to disclose *all* governance records (every witness set, revocation,
suspension) to prove that *one* of them is committed.

The 0.7 spec named this and deferred it: *"partial control-disclosure
(inclusion proof on the control tree)"*.

## 2. The disclosure

A holder produces, for one record at position `i`:

```
{
  "record": { ... the single control record ... },
  "leaf_index": i,
  "control_size": N,
  "inclusion_proof": [ "sha256:<hex>", ... ],   // RFC 6962 audit path
  "control_root_hash": "sha256:<hex>"           // the tree root it proves to
}
```

The leaf is `leafHash(record)` — the same RFC 6962 leaf the control tree is built
from (`0x00 || canonical(record)`), so the disclosure uses the identical Merkle
machinery as receipt inclusion proofs. The disclosure reveals **only** that one
record; the other `N-1` records stay private.

`buildControlDisclosure(controlRecords, index)` produces it;
`verifyControlDisclosure(disclosure, expectedControlRootHash?)` checks it.

## 3. Verification — and the trust chain

`verifyControlDisclosure(disclosure, expectedRoot)` recomputes
`leafHash(record)`, runs the RFC 6962 inclusion check against
`expectedRoot ?? disclosure.control_root_hash` at `(leaf_index, control_size)`,
and — when `expectedRoot` is supplied — additionally requires the disclosure's
own `control_root_hash` to equal it (so a holder cannot present a proof to a
self-chosen tree).

The complete chain an auditor follows (the `control verify-inclusion` CLI does
all three):

1. **STH signature** — the operator-signed STH verifies under the operator
   (sth) key, so its `control_root_hash` is authentic.
2. **Inclusion** — the disclosure's `control_root_hash` equals the STH's, and
   the inclusion proof verifies the record into that root at its position.
3. **Authorization** (optional, `--trust-root`) — `verifyControlRecord(record,
   trustRoot)` confirms the record is root/quorum-authorized.

Together: *"this root-authorized governance record is committed in the log at
this control position, under an STH the operator signed"* — without revealing
the rest of the control log.

## 4. Operator / auditor ceremony (CLI)

```
# holder: prove one record (by control-log index)
node axr-key-succession.js control prove control.jsonl <index> --out disclosure.json

# auditor: verify it against the committing STH (+ optional authorization)
node axr-key-succession.js control verify-inclusion disclosure.json sth.jsonl \
  --key op-pub.pem --trust-root trust-root.json
```

The verifier picks the STH whose `log_id` **and** `control_root_hash` match the
disclosure (the `log_id` filter prevents a coincidental cross-log root match in
a shared `sth.jsonl`). `--key` (the operator **public** key; `--op-key` /
`--pubkey` are accepted aliases) is **required** — without the STH signature the
`control_root_hash` is unauthenticated, so a holder could present a self-made
unsigned STH. `--trust-root` additionally checks the record is root-authorized.
Exit 0 on success, 1 on a verification failure, 2 on usage error.

## 5. SDK

`axr.control.buildControlDisclosure` / `axr.control.verifyControlDisclosure`
(pinned in the SDK surface test). The Python verifier mirrors
`verify_control_disclosure` for cross-impl parity (the control-tree Merkle
inclusion is byte-identical across Node and Python).

## 6. Threat-model notes

- **Forged proof:** a tampered record changes its leaf hash, so the inclusion
  check fails; a self-chosen root is rejected when the auditor supplies the STH
  root. Authenticity of the root itself comes from the STH signature (step 1).
- **Wrong-position / cross-tree:** `leaf_index`/`control_size` are bound into the
  RFC 6962 audit-path recomputation; a proof for one position does not verify at
  another, and a proof against one tree does not verify against another root.
- **Not a confidentiality guarantee about the record itself:** disclosure hides
  the *other* records, not the disclosed one. What is revealed is exactly the
  record the holder chose to prove.

## 7. Deferred (out of scope for 1.5)

- Consistency proofs between two control-tree sizes as a standalone holder tool
  (the monitor already checks control append-only across STHs).
- Range/multi-record disclosures in a single proof object — produce one
  disclosure per record for now.
