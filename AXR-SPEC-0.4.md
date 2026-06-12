# Agent Execution Receipt (AXR) — Protocol Specification 0.4

**Status:** Hardening layer. Additive over 0.3. The 0.2 wire format is frozen:
0.1/0.2/0.3 receipts verify byte-for-byte under the 0.4 verifier. This document
specifies only what 0.4 adds; for the receipt schema, Merkle construction,
anchoring, monitor, and threat model, see `AXR-SPEC-0.3.md`, which remains in
force.

---

## 1. What 0.4 adds over 0.3

0.3 made execution records tamper-evident and externally anchored. 0.4 narrows
the gaps that 0.3 named honestly in its non-guarantees:

1. **Redactable receipts** — erase PII (e.g. a prompt) without breaking the
   signature or the anchor, reconciling GDPR erasure with an append-only log.
2. **Side-effect attestation** — bind a receipt's claim about an external action
   to that external system's own record, narrowing N1 ("the operator signs its
   own homework").
3. **Trust root** — a root-signed provider key allowlist that makes the
   side-effect attestation key actually mean "this provider," closing the
   key->provider bootstrap.
4. **Key-role separation** — verify Signed Tree Heads with a key distinct from the
   receipt-signing key, so one compromised key does not forge the other's artifacts.
5. **Incremental anchoring** — an MMR cache so anchoring does not recompute the
   whole Merkle tree each run, with byte-identical roots.
6. **Strict mode** — a verifier gate that promotes quality signals to errors for CI.

Each feature is independent and optional. A 0.3 deployment that adopts none of
them keeps working unchanged.

---

## 2. Redactable receipts

### 2.1 Problem

An append-only, signed log cannot delete a field after the fact without breaking
the signature over that receipt. But data-protection law may require erasing
personal data (a prompt, a customer note). 0.4 resolves this with a commitment.

### 2.2 Construction

For a redactable receipt, designated fields are not signed by value. Instead each
field is committed as a salted leaf:

```
leaf_hash(field) = SHA-256(0x00 || canonical(field_value) || salt)
```

The receipt carries a `redactable_root` — the RFC 6962 Merkle root over the
field leaves — inside the signed body. The cleartext values and their salts live
in a separate, unsigned `redactable.fields[]` structure alongside the receipt.

- The **commitment** (`redactable_root`) is signed and anchored, so it is
  tamper-evident.
- The **cleartext** can be erased at any time. Erasing it leaves the commitment
  and the signature intact; the receipt still verifies.
- A present field is checked against its salted leaf; the salt prevents
  dictionary recovery of a low-entropy erased value.

### 2.3 Verification (check 13)

Where `redactable_root` is present, the verifier recomputes the field-tree root
from the present fields and confirms it equals the committed root, and confirms
each present field matches its salted leaf. Erased fields verify by absence — the
commitment stands without them. If the detail block is entirely absent, the
commitment is signed but not locally checkable; this is a notice (an error under
`--strict`, see §6).

Selective disclosure (SD-JWT / BBS+) and zero-knowledge proofs are the next layer
beyond this and are out of scope for 0.4.

---

## 3. Side-effect attestation

### 3.1 Problem (N1)

Anchoring proves *time and order*, not *truth at signing*. A step can claim "I
created calendar event X" and sign it; the signature does not make the claim true.

### 3.2 `side_effects[]`

A state-changing step may carry a signed `side_effects[]` array. Each entry:

```
{
  "type":        "calendar.event.created",
  "provider":    "google-calendar",
  "reference":   "evt_abc123",
  "evidence_hash": "sha256:..."  | null,
  "occurred_at": "2026-06-08T08:00:00.000Z",
  "attestation": { ... } | absent
}
```

`side_effects` is part of the signed receipt body, so it is tamper-evident and
anchored. Two honesty levels:

- **Recheckable** (no attestation): the external `reference` plus a hash of the
  provider's response let an auditor independently re-fetch and compare. Not
  self-proving, but independently checkable — stated as such, not overclaimed.
- **Attested** (provider co-sign): the external service signs the entry with its
  own key, binding the event to a party other than the operator:

```
"attestation": {
  "algorithm":  "ed25519",
  "public_key": "-----BEGIN PUBLIC KEY----- ...",
  "signature":  "<base64 over canonical(entry without attestation)>"
}
```

### 3.3 Verification (check 14)

Each entry is checked for well-formedness. If it carries an attestation, the
attestation signature must verify over the canonical entry (minus the attestation
field). A failed attestation is an error; a missing attestation is a notice
(recheckable). Whether the attesting key legitimately represents the named
provider is decided by the trust root (§4) — without one, the key->provider
binding is unverified and reported as such.

---

## 4. Trust root

### 4.1 Problem

A plain attestation only proves *some* key signed the entry. Nothing stops an
operator from signing with its own key and naming the provider `google-calendar`.

### 4.2 Record

A trust root is an independent, root-signed, append-resistant allowlist:

```
{
  "axr_version": "0.4",
  "record_type": "trust_root",
  "issued_at":   "2026-06-08T00:00:00.000Z",
  "root_public_key": "-----BEGIN PUBLIC KEY----- ...",
  "providers": [
    { "provider": "google-calendar", "public_keys": ["-----BEGIN PUBLIC KEY----- ..."] },
    { "provider": "stripe",          "public_keys": ["..."] }
  ],
  "signature": "<base64 over canonical(record without signature)>"
}
```

The signature is over the canonical record without `signature`, so the allowlist
cannot be extended or altered after issuance without invalidating it. The root key
is held by a party **independent of the operator** — an auditor, a consortium, or
a published list. That independence is what makes the binding meaningful; AXR
verifies the document's integrity, not the root key's standing in the world.

### 4.3 Effect on verification

When a trust root is supplied (verifier `--trust-root`), an attestation counts as
`attested` only if its `public_key` appears in the trust root for the entry's
`provider`. Otherwise it is downgraded to a problem ("key not in trust root"),
because the `attested` claim is not trustworthy. Without a trust root, behavior is
unchanged (backward compatible).

Build and verify a trust root with `axr-trust-root.js` (`build`, `verify`).
Core functions: `buildTrustRoot`, `verifyTrustRoot`, `trustRootHasKey`.

---

## 5. Key-role separation

The receipt-signing key and the Signed-Tree-Head-signing key are distinct roles.
The anchoring sidecar already signs STHs with its own key. The 0.4 verifier honors
this with `--sth-key <pem>`: STHs are verified with that key, receipts with the
main key. A compromised receipt key cannot forge tree heads, and a compromised STH
key cannot forge receipts. Without `--sth-key`, the main key verifies both
(backward compatible). Hardware/threshold key management remains out of scope.

*0.5 generalizes this section: a role's key becomes a function of tree
position (key succession), with `--sth-key` as the single-key special case —
see `AXR-SPEC-0.5.md` §6.*

---

## 6. Strict mode

Some verifier signals are not tamper evidence but quality deficiencies: a null
`input_hash` (a node left no `__axr_input` marker), an absent redactable detail
block, an unknown `reproducibility.level`. By default these are notices and the
log still verifies (exit 0). `--strict` promotes them to errors (exit 1), for use
as a CI gate. Strict mode does not change what counts as tampering; it only raises
the bar on completeness.

---

## 7. Incremental anchoring (MMR)

### 7.1 Construction

The RFC 6962 tree over n leaves decomposes left-to-right into perfect subtrees
("peaks") whose sizes follow the binary representation of n. AXR maintains these
peaks in an `anchor-state.json` cache beside `receipts.jsonl`:

```
{ "leaf_count": N, "peaks": [ { "hash": "sha256:...", "size": 2^k }, ... ], "root_hash": "sha256:...", "updated_at": "..." }
```

Appending a leaf is a binary-counter merge: push a size-1 peak, then while the two
rightmost peaks are equal size, combine them with `nodeHash(left, right)` into a
peak of double size. This is O(log n) work and O(log n) storage per leaf.

The root folds the peaks from the right:
`root = nodeHash(peak_1, nodeHash(peak_2, ... nodeHash(peak_{m-1}, peak_m)))`,
which is exactly the RFC 6962 MTH recursion. The MMR root is therefore
**byte-identical** to `merkleRootFromLeaves` for every n, not only at power-of-two
boundaries. `axr-incremental-test.js` proves equality for n = 1..40.

### 7.2 Cache integrity

Before trusting the cache, the sidecar checks it structurally (`mmrValid`): peak
sizes are powers of two, strictly decreasing, and sum to `leaf_count`, and
`leaf_count` does not exceed the leaves actually present. A corrupt or stale cache
fails this O(log n) check and the sidecar rebuilds from scratch — the resulting
root is identical, so a bad cache can only cost time, never correctness.

Core functions: `mmrAppend`, `mmrRoot`, `mmrValid`.

---

## 8. OpenTimestamps loop closure

0.3 submitted the anchor root to OTS calendars but did not close the loop in code.
0.4 adds:

- `axr-anchor.js upgrade <anchors.jsonl>` — re-queries the calendars
  (`GET /timestamp/<digest>`) and promotes a pending entry to `confirmed`,
  recording the upgrade response.
- verifier `--online` — performs the same calendar confirmation during check 12.

**Trust boundary (explicit).** This confirms calendar-level inclusion: the digest
is known to an independent timestamp service. The final Bitcoin-block
proof-of-work verification is delegated to the standard `ots verify` CLI over the
recorded responses. AXR does not reimplement Bitcoin SPV; doing so would add
exactly the kind of dependency and attack surface the project avoids.

---

## 9. Verifier checks and flags (0.4 summary)

Checks 1–12 are as in 0.3. 0.4 adds:

- **13. Redactable commitment integrity** — field-tree root equals
  `redactable_root`; present fields match their salted leaves; erased fields
  verify by absence.
- **14. Side-effect attestation** — entries well-formed; attestation (if present)
  verifies; key bound to provider via trust root when supplied.

Flags: `--strict`, `--sth-key <pem>`, `--trust-root <json>`, `--online`.

Exit codes are unchanged: 0 valid, 1 problem found, 2 usage/load error.
