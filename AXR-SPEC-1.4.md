# AXR 1.4 — Witness suspension (temporary, auto-expiring)

Status: **additive over the frozen 1.0 contract.** 1.4 adds one new control-log
record type (`witness_suspension`) and one new consumer **notice** code
(`WITNESS_SUSPENDED`). No existing wire format, canonicalization, CLI exit code,
or 0.2–1.3 behaviour changes: a log with no `witness_suspension` record verifies
exactly as before. Landed in a 1.x release under the 1.x additive-record-type
policy (`AXR-SPEC-1.0.md`).

## 1. What 1.4 adds over 1.1

The 0.8 witness layer has two ways to remove a witness:

- **Slow revoke** (0.8): issue a new `witness_set` effective from a future
  boundary.
- **Emergency revoke** (1.1, `witness_revocation`): invalidate a witness key
  *permanently* from a `revoked_at_tree_size` boundary — the witness is
  compromised, and a cosignature past the boundary is a **violation**
  (`WITNESS_REVOKED`).

1.4 adds the missing **temporary** case. A witness may be unavailable for a
known interval — maintenance, a planned key rotation, a transient outage — while
remaining **trusted** (not compromised). `witness_suspension` excludes a witness
over a `[from, until)` `tree_size` window; from `until` it counts **again,
automatically**, with no new `witness_set`. Because suspension is benign, a
suspended witness's cosignature inside the window is a **notice**
(`WITNESS_SUSPENDED`), **not** a violation — the key distinction from revocation.

## 2. `witness_suspension` — the record (in the control log)

```
{
  "axr_version": "1.4",
  "record_type": "witness_suspension",
  "log_id": "axr:agent:v1",
  "suspended_fingerprint": "sha256:<hex>",       // the witness key
  "suspended_from_tree_size": <n>,               // inclusive
  "suspended_until_tree_size": <m>,              // EXCLUSIVE, m > n
  "reason": "...",
  "issued_at": "<ISO8601>",
  "signature": "<base64>"                         // single-key root mode
  // OR quorum mode: "signatures": [ { "key_fingerprint", "signature" }, ... ]
}
```

Signed by the **trust-root** authority (single key or M-of-N quorum), same as
`witness_set` / `witness_revocation`. Lives in the **control log** (0.7),
STH-committed. A consumer that does not understand it fails closed on the unknown
control record type (0.7 P2); 1.4 consumers add it to the accepted set.

## 3. Semantics — a half-open window, auto-expiring

For a witness `F` suspended over `[from, until)` and an STH at `tree_size = T`:

- **T < from** or **T ≥ until** — `F` counts normally (before the window, or
  after it auto-expires).
- **from ≤ T < until** — `F`'s cosignature **does not count** toward the
  threshold; if present on the STH, the consumer emits `WITNESS_SUSPENDED`
  (a **notice**, never a violation).

The window is **half-open** so suspensions can tile a timeline without overlap.
A fingerprint may have several disjoint suspension windows; membership is "T in
any window". 

**The threshold does not shrink** (as with revocation). If a suspension drops
the valid count below the threshold, the STH is `UNDER_WITNESSED` (notice by
default, violation under `--require-witnesses`) for the window's duration — and
recovers automatically at `until`. Suspension never *by itself* fails a log; it
only withholds the suspended witness's contribution.

**Precedence over revocation.** If a fingerprint is both revoked (permanent) and
suspended at a given `tree_size`, **revocation wins**: it is treated as
`WITNESS_REVOKED` (violation), not `WITNESS_SUSPENDED`. A permanent compromise
signal is never downgraded to a benign one.

## 4. Operator ceremony (CLI)

Single-key:

```
node axr-key-succession.js suspend-witness <root-priv.pem> \
  --log-id <id> (--suspended <witness-pub.pem> | --suspended-fingerprint sha256:<hex>) \
  --from <tree_size> --until <tree_size> [--reason text] > witness-suspension.json
```

Quorum (M-of-N), reusing the 0.6 ceremony:

```
node axr-key-succession.js body witness-suspension --log-id <id> \
  (--suspended <pub.pem> | --suspended-fingerprint sha256:<hex>) --from <n> --until <m> > body.json
node axr-key-succession.js sign body.json signer1-priv.pem > part1.json   # per signer
node axr-key-succession.js assemble body.json part1.json part2.json --verify <trust-root.json> > witness-suspension.json
```

Add to the control log (verified before append): `control add`. Inspect:
`axr-key-succession.js verify witness-suspension.json <anchor>`.

## 5. Consumer behaviour and codes

Monitor and both verifiers collect root-verified `witness_suspension` records
from the control log (rejecting forged/foreign-`log_id` ones as
`CONTROL_ROOT_MISMATCH`, the same fail-closed path as the other witness
governance), fold them into the witness timeline, and apply the window rule
per STH:

- `WITNESS_SUSPENDED` — **new** in 1.4. A suspended witness's cosignature is
  present on an STH inside its window. Always a **notice** (never a violation);
  Informational (severity 1) in the OCSF mapping. The monitor and the JS
  verifier emit it; the Python verifier is verdict-only and does not print it
  (it still does not count the suspended cosignature — the verdict matches).
- `UNDER_WITNESSED` keeps its 0.8 meaning; a suspension that drops the valid
  count below threshold surfaces as `UNDER_WITNESSED`.

No flags are added.

## 6. Threat-model notes

- **Suspension-as-DoS:** a suspension can only *withhold* a witness, and only a
  valid root/quorum signature is accepted (a forged one is
  `CONTROL_ROOT_MISMATCH`). The worst an authorized-but-careless suspension does
  is push a log to `UNDER_WITNESSED` for the window — which recovers at `until`
  and is a notice unless the consumer runs `--require-witnesses`.
- **No silent trust downgrade:** suspension cannot turn a *revoked* (compromised)
  witness back into a counting one — revocation has precedence. And suspension
  cannot lower the threshold; it can only remove a contribution.
- **Auto-expiry is policy, not a clock:** `until` is a `tree_size`, not
  wall-clock — consistent with the rest of AXR. The witness counts again from the
  first STH at `tree_size ≥ until`.

## 7. Deferred (out of scope for 1.4)

- Indefinite suspension (no `until`) — use `witness_revocation` for permanent
  removal; suspension is by definition bounded.
- Witness-initiated self-suspension — suspension is a root/quorum authority act.
- Wall-clock windows — `tree_size` remains the only clock.
