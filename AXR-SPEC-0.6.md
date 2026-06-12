# Agent Execution Receipt (AXR) — Protocol Specification 0.6

**Status:** Root-lifecycle hardening layer. Additive over 0.5. The 0.2 wire
format remains frozen; every 0.6 feature is opt-in — a 0.5 deployment that
adopts none of it keeps working unchanged, and a deployment without a trust
root keeps the 0.3/0.4 TOFU behavior. This document specifies only what 0.6
adds; `AXR-SPEC-0.3.md`, `AXR-SPEC-0.4.md` and `AXR-SPEC-0.5.md` remain in
force.

---

## 1. What 0.6 adds over 0.5

0.5 moved the trust anchor from the operator key to an independent root key —
and thereby concentrated risk in that one key: stolen, it forges successions
without limit; lost, no further rotation can ever be authorized. 0.6 closes
the root key's own lifecycle:

1. **Quorum root (M-of-N multi-signature)** — the trust root declares a key
   *set* and a threshold; records verify with M distinct signatures.
2. **Root rotation and recovery** — the root set itself rotates: a successor
   trust root is authorized by the predecessor's quorum, chained from a
   pinned genesis.
3. **Revocation** — a key's signing power can be retired from a tree-size
   boundary, with anchored-evidence semantics for the past.
4. **Operator ceremony CLI** — multi-party signing without hand-crafted
   canonical JSON (`body` → `sign` → `assemble`), with self-lockout
   protection.

## 2. Quorum root

### 2.1 Record

The trust root may declare, instead of `root_public_key`:

```
"root_keys":  ["<PEM>", "<PEM>", "<PEM>"],
"threshold":  2,
"signatures": [ { "key_fingerprint": "sha256:...", "signature": "<base64>" }, ... ]
```

Exactly one mode is valid per record: `root_public_key` + `signature`
(single, 0.5) or `root_keys` + `threshold` + `signatures` (quorum). Mixed
mode is invalid. The same `signatures` shape applies to quorum-signed
`key_succession` and `key_revocation` records.

The signed message is the canonical record without the `signatures` field. A
legacy `signature` field, if present, is *inside* the signed body — appending
one after the fact breaks the quorum signatures (tamper-evident by
construction).

### 2.2 Verification invariants (all fail-closed)

A quorum-signed record is valid only if **every** signature entry is clean
and at least `threshold` distinct declared signers verified. Any anomaly
rejects the record even if the quorum is otherwise met:

- a signer not in the declared set,
- a duplicated signer,
- an invalid signature from a declared signer,
- a malformed entry,
- a signature set not strictly ascending by `key_fingerprint`.

The ordering rule makes the signature set canonical: two assemblies of the
same parts are byte-identical, so record hashes (pool dedup, chain hashes)
are stable regardless of who assembled.

### 2.3 What this is — and is not (honest naming)

This is **multi-signature, not threshold cryptography** (no BLS/FROST, no
new dependencies; the policy goal is met with plain Ed25519). Root compromise
does not become impossible — its failure mode changes from *single-key
compromise* to *quorum compromise, signer collusion, policy misconfiguration,
or key co-location*. Deployments should treat quorum policy as part of the
threat model:

- **Recommended default: 2-of-3** (a recommendation, not an enforcement;
  M=1/N=1 remains valid as the 0.5-compatible case).
- Keep quorum keys on separate machines, ideally with separate custodians;
  a quorum stored in one place is a single key with extra steps.
- Replacing a quorum member, handling a lost signer, and detecting a
  colluding quorum are governance procedures (root rotation, §3, is the
  in-protocol tool for the first two; the third is out-of-protocol by
  nature — no log can police its own root set's intentions).

## 3. Root rotation and recovery

### 3.1 Chain

A successor trust root carries:

```
"predecessor_trust_root_hash": "sha256:<hash of the full predecessor record>"
```

and its `signatures` are made by the **predecessor's** declared key set,
meeting the predecessor's threshold. The successor declares its own (new)
key set in its signed body. Consequences:

- A successor is **never valid standalone** — only as part of a chain
  starting from a pinned, self-valid genesis. There is no self-authorizing
  root.
- A 0.5 single-key root rotates to a quorum successor by signing it with the
  old single key (1-of-1 quorum) — this is the migration path.
- **Recovery:** while M of the N old signers remain, they authorize a fresh
  set in-protocol. Below M survivors, recovery is out-of-band (a new trust
  root distributed like the original genesis) — stated, not hidden.

### 3.2 Consumption

`--trust-root` inputs may be a single record, an array, or a JSONL chain in
the monitor and both verifiers. The chain head must self-verify and carry no
predecessor hash; each link is checked against its predecessor's quorum; the
**effective** root (keys, genesis entries, providers) is the last record.

The monitor pins the **genesis hash** in its journal
(`trust_root_genesis_hash`). A different genesis on a later poll — even one
heading a self-consistent chain — is `TRUST_ROOT_CHANGED`, a violation,
fail-closed. This is what stops an attacker from substituting an entirely
fabricated chain.

**Migration duty (explicit).** Consumers verify succession and revocation
records against the *effective* root — the chain tail. After a root
rotation, records signed by the predecessor set therefore no longer verify:
every still-relevant succession/revocation must be **re-issued under the new
quorum** as part of the rotation ceremony. This is not an integrity gap (the
alternative — accepting old-root signatures indefinitely — would defeat the
rotation); it is an operator obligation, and skipping it is self-lockout.

## 4. Revocation

### 4.1 Record

```
{
  "axr_version": "0.6",
  "record_type": "key_revocation",
  "log_id": "...", "role": "sth" | "receipt",
  "revoked_fingerprint": "sha256:...",
  "revoked_at_tree_size": N,
  "reason": "compromise" | ...,
  "issued_at": "...",
  <signature | signatures>   (root/quorum, as in §2)
}
```

Applied to the key timeline, a revocation marks the matching segments with
`revoked_from = N` (the earliest boundary wins if several records target the
same key). Revocation retires *signing power*; it does not rewrite chain
history or the segment's `authorized` status.

### 4.2 Three-tier semantics (the hard decision, stated)

For an artifact whose era-key is revoked at boundary `N`:

1. **Position < N, with anchored evidence** (a verified `anchor_ref`
   inclusion proof; for STHs, the witnessed journal/STH stream): **valid**.
   The certified past does not retroactively rot.
2. **Position < N, without evidence: fail-closed.** A stolen old key must
   not be able to fabricate a "pre-boundary" narrative after the fact —
   unproven claims about the past are rejected.
3. **Position ≥ N: `KEY_REVOKED`** (violation), regardless of signature
   validity.

Wall-clock "when did we learn of the compromise" stays out of the trust path;
the boundary is `revoked_at_tree_size`, chosen by the issuer.

A revocation that does not verify (forged, foreign log) is
`REVOCATION_UNAUTHORIZED` — a revocation-as-DoS attempt against a legitimate
key is itself a detectable event. A key revoked with no successor leaves no
valid key from the boundary on: everything after fails, loudly, until a
succession lands. That is the intended fail-closed posture.

## 5. Operator ceremony (CLI)

Multi-party signing must not involve hand-edited canonical JSON — that path
ends in self-lockout. `axr-key-succession`:

```
body succession|revocation|root-successor ...   -> unsigned canonical body
sign <body.json> <signer-priv.pem>              -> one signer's part
assemble <body.json> <part...> --verify <anchor>-> the final record
```

`sign` refuses an already-signed body. `assemble` orders parts
deterministically, rejects duplicates, and with `--verify` refuses to emit a
record the consumers would reject. `verify` dispatches on `record_type` and
accepts raw-PEM, trust-root and chain anchors (a chain verifies before its
effective root is trusted). `revoke` builds a single-key revocation directly.

Without `--verify`, `assemble` emits the merged record with a loud warning
only — it cannot check a quorum it has no anchor for. **Operational rule: a
production record release always uses `assemble --verify <anchor>`.** Treat
an unverified assembly as a draft.

## 6. Monitor and verifier codes (0.6 summary)

New codes: `KEY_REVOKED` (violation, Critical in the OCSF mapping),
`TRUST_ROOT_CHANGED` (violation, Critical), `REVOCATION_UNAUTHORIZED`
(violation, High). All other 0.5 codes and behaviors are unchanged. New
flags: `--revocations <jsonl>` (monitor and both verifiers); `--trust-root`
now chain-capable everywhere.

Revocations travel out-of-band in 0.6 (like receipt-role successions). An
in-log distribution channel (a control log committed by the STH body) is the
planned 0.7 direction.

## 7. Deferred (explicitly out of scope for 0.6)

- **Control log** — in-log, anchored distribution of receipt-role
  successions and revocations (`AXR-0.6-SCOPE.md` records the design
  direction).
- **Wall-clock validity windows** — still rejected by design.
- **True threshold cryptography, HSM integration** — unchanged from 0.5.
- **Quorum-member collusion detection** — out of protocol by nature; the
  spec's contribution is naming it (§2.3).

## 8. Compatibility summary

| Input | 0.6 tooling behavior |
|---|---|
| no trust root | 0.3/0.4 TOFU pinning, bit-for-bit |
| 0.5 single-key trust root | identical to 0.5; may rotate to a quorum successor |
| quorum trust root, no rotations | quorum verification everywhere, nothing else changes |
| trust-root chain | head pinned, effective root governs |
| no revocations supplied | timelines carry no `revoked_from`; 0.5 behavior |

The 0.2 wire format, the RFC 6962 byte vectors, and all exit-code contracts
are unchanged.
