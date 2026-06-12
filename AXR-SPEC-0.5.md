# Agent Execution Receipt (AXR) — Protocol Specification 0.5

**Status:** Key-lifecycle layer. Additive over 0.4. The 0.2 wire format remains
frozen: 0.1–0.4 logs verify byte-for-byte under the 0.5 tooling, and every 0.5
feature is opt-in — a deployment that adopts none of it keeps working unchanged.
This document specifies only what 0.5 adds; for the receipt schema, Merkle
construction, anchoring, monitor, and threat model see `AXR-SPEC-0.3.md` and
`AXR-SPEC-0.4.md`, which remain in force.

---

## 1. What 0.5 adds over 0.4

0.4 separated key roles (§5 there): the receipt-signing key and the
STH-signing key are distinct. But both were still **pinned**: the monitor and
verifier learned one key per role and treated any change as suspect (TOFU).
That made a legitimate, scheduled key rotation indistinguishable from a silent
key compromise — operationally, every rotation looked like an attack.

0.5 resolves this with **key succession**: the trust anchor is no longer the
operator key (which is exactly the thing that rotates) but the independent
**root key** — the same key that signs the trust root (0.4 §4). Every operator
key is either declared at genesis by the trust root or authorized by a
root-signed succession record:

```
root key (pinned, independent)
  └─ signs trust root  ──────────► declares genesis keys (per log, per role)
  └─ signs key_succession ───────► authorizes successor keys
                                     └─ successor signs STHs / receipts
```

What this buys, concretely:

- **`KEY_ROTATED_AUTHORIZED`** — a rotation backed by a root-signed succession
  is a notice, not an alarm.
- **`KEY_CHANGED_UNAUTHORIZED`** — a key change *without* root authorization
  (forged succession, foreign-log succession, unauthorized pin swap) is a
  violation, loudly.
- **Rotation-spanning verification** — a log whose receipts and STHs were
  signed by several keys over its lifetime verifies as one continuous log.

---

## 2. Records

### 2.1 Extended trust root (genesis)

The 0.4 trust root declares provider keys. 0.5 extends the same record — same
signature scheme, same root key — with per-log genesis operator keys:

```
{
  "axr_version": "0.5",
  "record_type": "trust_root",
  "issued_at":   "...",
  "root_public_key": "-----BEGIN PUBLIC KEY----- ...",
  "providers": [ ... as in 0.4 ... ],
  "logs": [
    { "log_id": "axr:agent:v1",
      "genesis": { "sth": "<PEM>", "receipt": "<PEM>" } }
  ],
  "signature": "<base64 over canonical(record without signature)>"
}
```

The genesis key is declared by the trust root, **not** created by a succession
record — anyone could mint a "first" succession, so the starting point must be
root-anchored. This removes the TOFU weakness at the origin of the chain. A
0.4 trust root (no `logs`) remains valid; it simply enables no succession.

### 2.2 `key_succession`

A root-signed record authorizing one rotation:

```
{
  "axr_version": "0.5",
  "record_type": "key_succession",
  "log_id": "axr:agent:v1",
  "role": "sth" | "receipt",
  "predecessor_fingerprint": "sha256:<hex>",
  "successor_public_key": "-----BEGIN PUBLIC KEY----- ...",
  "successor_fingerprint": "sha256:<hex>",
  "effective_from_tree_size": N,
  "reason": "scheduled" | "compromise" | ...,
  "issued_at": "...",
  "signature": "<base64 over canonical(record without signature)>"
}
```

- `predecessor_fingerprint` is never null (genesis comes from the trust root).
- `successor_fingerprint` must equal the fingerprint of
  `successor_public_key`; a verifier checks this consistency explicitly.
- Key fingerprints are `sha256:<hex>` over the PEM body with headers and all
  whitespace stripped — byte-identical across the sidecar, monitor, verifier,
  and the Python implementation.
- Verification of a succession record = structural checks + fingerprint
  consistency + Ed25519 signature against the **root** public key.

### 2.3 One clock: `tree_size`

The authoritative order is the Merkle position — `tree_size` for STHs, the
1-based leaf position (`leaf_index + 1`) for receipts. The operator cannot
back-date a Merkle position without breaking consistency proofs. Wall-clock
`issued_at` is informative only. There are deliberately **no**
`not_before`/`not_after` windows: an operator-controlled clock does not belong
in the trust path.

**Boundary rule (off-by-one fixed).** The successor signs artifacts at
position `>= effective_from_tree_size`; the predecessor signs positions
`< effective_from_tree_size`. The same rule, with the same arithmetic, applies
to STHs (by `tree_size`) and receipts (by leaf position): with
`effective_from_tree_size = N`, the N-th leaf and the size-N STH already
belong to the successor.

---

## 3. Key timeline

Consumers (monitor, verifier) build a per-role **timeline** from the genesis
key plus all known succession records:

1. Only root-verified successions of the matching `role` and `log_id` enter
   the timeline. Everything else is rejected *before* its key is used for
   anything — order of operations is a hard invariant.
2. Records sort by `effective_from_tree_size`. Each must reference the
   currently active key as its predecessor (predecessor-linked chain).
3. **Transitive authorization.** A segment is authorized only if its link is
   intact *and* every earlier segment was authorized. A broken link poisons
   everything after it — later records that chain "correctly" onto the broken
   key do not heal back to authorized. Otherwise an attacker could enter via
   one broken jump and have all subsequent rotations appear legitimate.
4. **Forks are fail-closed.** Two (or more) root-signed successions with the
   same `effective_from_tree_size` would mean two possible successor keys for
   the same tree size. No fork branch is authorized, and the chain is poisoned
   from that boundary on. There is no first-wins: monitors with different
   input order or partial visibility must never accept different active keys
   for the same `tree_size`.
5. **Degraded mode.** If the trust root carries no genesis for the log/role,
   no rotation can be authorized. The consumer falls back to the 0.4 behavior
   (TOFU pinning, every key change critical) and says so explicitly.
6. An invalid trust root is `TRUST_ROOT_INVALID` and fail-closed: no key
   claim derived from it is honored.

Lookup: the key valid at position `p` is the timeline entry with the largest
`from_tree_size <= p`. The genesis entry has `from_tree_size = 0`, so a lookup
always resolves.

---

## 4. Embedded succession (withholding fix)

A succession record that never reaches the monitor is useless — an operator
could rotate keys and simply not distribute the authorization. 0.5 closes this
in-band: **the successor key's first STH embeds the full root-signed
succession record** as `embedded_succession` in the signed STH body.

- The field is covered by the STH signature *and* the STH chain hash, so the
  embedded record is tamper-evident and anchored like everything else.
- Embedding happens once (idempotent): later STHs revert to the plain shape.
- The sidecar (`axr-anchor.js --succession`) refuses to embed a record that
  (a) is not `role=sth`, (b) belongs to another `log_id`, (c) does not
  authorize the key actually signing the STH, or (d) precedes its own
  boundary (`tree_size < effective_from_tree_size`).
- The monitor extracts and root-verifies `embedded_succession` **before** the
  new key is used to check anything.

Receipt-role successions have no STH to ride in; they travel out-of-band
(verifier `--successions` file). Their authorization is identical.

---

## 5. Monitor behavior (0.5)

With `--trust-root` (and optionally `--successions`), the monitor replaces
single-key STH verification with the timeline lookup: every STH verifies with
the key valid at its `tree_size`. New codes:

- `KEY_ROTATED_AUTHORIZED` (notice) — a rotation backed by the timeline; also
  reported when the monitor's own pinned key file is updated to an authorized
  successor (the journal pin follows).
- `KEY_CHANGED_UNAUTHORIZED` (violation) — an embedded or supplied succession
  that fails root verification or belongs to a foreign log; an STH signed by
  a key whose timeline segment is unauthorized; or a pin swap to a key not on
  the authorized timeline.
- `TRUST_ROOT_INVALID` (violation, fail-closed) — the poll stops before any
  key claim is honored.
- A signature that fails against the timeline key remains `BAD_SIGNATURE`
  (possible unannounced key change — the monitor cannot identify an unknown
  signer from an Ed25519 signature alone).

**Journal extension.** The journal gains `active_key_fingerprint` (the key
valid at the largest witnessed tree size) and `succession_chain_hash` — the
canonical hash of the verified succession set, sorted by
`effective_from_tree_size` with the records' canonical hash as tie-break, so
two honest monitors seeing the same set in any input order compute the same
value. `compareJournals` reports differing chain hashes as a conflict — a
split view of the *key history* — but only when both journals carry one
(0.3-era journals lack the field; one-sided absence is a timing artifact, not
a conflict).

Without a trust root, monitor behavior is bit-for-bit the 0.3/0.4 TOFU
pinning, `KEY_CHANGED` included.

---

## 6. Verifier behavior (check 15) — and §5 of 0.4, updated

0.4 §5 ("Key-role separation") gave each role its own key but assumed one key
per role for the life of the log. 0.5 generalizes that section: a role's key
is a **function of tree position**, not a constant. `--sth-key` remains the
single-key special case and keeps working unchanged.

With a genesis-bearing `--trust-root`, the verifier builds both role
timelines (receipt-role records from `--successions`; sth-role records from
`--successions` and from `embedded_succession` found in the STH stream) and
verifies every signature with the key of its era: receipts by leaf position,
STHs by `tree_size`, under the §2.3 boundary rule. Unauthorized segments
report `KEY_CHANGED_UNAUTHORIZED`. The `log_id` resolves from `--log-id`, the
first STH, or a single-log trust root, in that order.

The Python verifier (`axr_verify.py`) mirrors the construction in full —
fingerprints, trust-root and succession verification, timeline (including
transitive authorization and fail-closed forks), and key selection — with
zero dependencies. `axr-verify-succession-test.js` runs both implementations
against the same rotated-log fixtures and requires agreement on accept *and*
reject (control, happy path, boundary-violating signature, forged succession,
post-rotation tamper, forked succession).

Flags added in 0.5: `--successions <jsonl>`, `--log-id <id>` (verifier);
`--succession <json>` (sidecar); `--trust-root <json>`, `--successions
<jsonl>` (monitor).

---

## 7. CLI

`axr-key-succession.js` (in `bin` as `axr-key-succession`):

- `build <root-priv.pem> --log-id <id> --role sth|receipt
  (--predecessor <pub.pem> | --predecessor-fingerprint sha256:<hex>)
  --successor <pub.pem> --effective-from <n> [--reason <text>]` — emits the
  root-signed record after self-verification.
- `verify <record.json> <root-pub.pem | trust-root.json>` — the anchor may be
  a raw PEM or a signed trust root; a trust root must verify itself before
  its `root_public_key` is used (no self-made anchors).
- `fingerprint <pub.pem>` — prints a key fingerprint for rotation prep.

---

## 8. Deferred (explicitly out of scope for 0.5)

Named here so their absence is a decision, not an oversight:

- **Revocation** — a succession authorizes from a boundary; 0.5 has no record
  to *retire* a key mid-era. Compromise response today = rotate forward with
  `reason: "compromise"`.
- **Threshold signing** — the root key is a single key; M-of-N issuance of
  successions is future work.
- **Recovery ceremony** — loss of the root key has no in-protocol recovery;
  it requires a new trust root distributed out-of-band.
- **Wall-clock validity windows** — rejected by design (§2.3), revisited only
  if a trustworthy external time source enters the model.

---

## 9. Compatibility summary

| Input | 0.5 tooling behavior |
|---|---|
| 0.1–0.4 log, no trust root | identical to 0.4 (TOFU pinning, `KEY_CHANGED`) |
| 0.4 trust root (no `logs`) | valid; succession disabled; explicit degraded notice |
| 0.5 trust root, no rotations yet | genesis keys verify everything; no behavior change |
| rotated log + trust root + successions | verifies as one continuous log |

The 0.2 wire format, the RFC 6962 byte vectors, and all existing exit-code
contracts are unchanged.
