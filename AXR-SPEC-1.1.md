# AXR 1.1 — Emergency witness-revocation

Status: **additive over the frozen 1.0 contract.** 1.1 adds one new control-log
record type (`witness_revocation`) and one new consumer violation code
(`WITNESS_REVOKED`). It changes no existing wire format, canonicalization, CLI
exit code, or 0.2–1.0 behaviour: a log with no `witness_revocation` record
verifies exactly as it did at 1.0. The 1.x additive-record-type policy
(`AXR-SPEC-1.0.md`) is the basis for landing this in a 1.x release.

## 1. What 1.1 adds over 1.0

The 0.8 witness layer can only remove a witness by a **slow revoke**: issue a
new `witness_set` effective from a future `tree_size`. Until that boundary the
old witness still counts. If a witness key is **compromised** (signing
split-views, stolen, or the holder is no longer trusted), its cosignatures must
stop counting **immediately**, possibly from a `tree_size` already reached.

1.1 adds `witness_revocation`: a quorum/root-signed control-log record that
invalidates one specific witness fingerprint from a `revoked_at_tree_size`
boundary. It is the structural mirror of the 0.6 `key_revocation`.

## 2. `witness_revocation` — the record (in the control log)

```
{
  "axr_version": "1.1",
  "record_type": "witness_revocation",
  "log_id": "axr:agent:v1",
  "revoked_fingerprint": "sha256:<hex>",     // the witness key being revoked
  "revoked_at_tree_size": <n>,               // invalid for STHs with tree_size >= n
  "reason": "...",
  "issued_at": "<ISO8601>",
  "signature": "<base64>"                     // single-key root mode
  // OR, in quorum mode (0.6 root):
  "signatures": [ { "key_fingerprint": "sha256:<hex>", "signature": "<base64>" }, ... ]
}
```

- It is signed by the **trust-root** authority — the same single key or M-of-N
  quorum that signs the `witness_set` (the witness circle is root-controlled,
  not operator-controlled). The signed body is the record **without** the
  `signature`/`signatures` field, canonicalized (RFC 8785/JCS).
- It lives in the **control log** (0.7 channel), distributed and STH-committed
  exactly like `witness_set`. It is **not** in the trust root.
- A consumer that does not understand `witness_revocation` would fail closed on
  the unknown control record type (0.7 P2). 1.1 consumers add it to the accepted
  set, so the version gate is explicit.

## 3. Semantics — a clean two-tier rule

For a witness fingerprint `F` revoked at `revoked_at_tree_size = R`, and an STH
at `tree_size = T`:

- **T < R** — `F`'s cosignature still counts toward the threshold (the
  revocation has not taken effect yet at this tree head).
- **T ≥ R** — `F`'s cosignature **does not count**, and if it is present on the
  STH the consumer raises `WITNESS_REVOKED` (always a violation, like the 0.6
  `KEY_REVOKED`). The operator is expected to stop attaching a revoked witness's
  cosignature; its continued presence past the boundary is a finding.

This is **simpler than the 0.6 key-revocation three-tier rule** and
deliberately so: for STHs, `tree_size` is the unambiguous clock the witness
layer already uses, so there is no "pre-boundary without anchored evidence"
middle tier. The boundary alone decides.

**The threshold does not shrink.** Revoking a witness reduces the count of
*available valid* signers but leaves the `witness_set` threshold unchanged. If
the revocation drops the effective valid cosignatures below the threshold, the
STH is `UNDER_WITNESSED` (notice by default, violation under
`--require-witnesses`) until a new `witness_set` restores the circle. This is
the honest, fail-closed outcome: emergency revocation degrades trust to
"insufficiently witnessed" rather than silently lowering the bar.

If multiple revocations name the same fingerprint, the **earliest**
`revoked_at_tree_size` wins (a revocation cannot be postponed by a later one).

## 4. Recovery

To restore the witness circle after an emergency revocation, issue a new
`witness_set` (effective from a boundary at or after the revocation) that
declares the replacement witnesses, and have the operator obtain fresh
cosignatures on the STHs in that range. The revocation remains in force for the
revoked fingerprint regardless of later sets.

**Operator note:** because the threshold does not shrink (§3), a revocation that
drops the valid count below threshold puts the log in `UNDER_WITNESSED` until the
circle is restored — which halts a strict (`--require-witnesses`) consumer. To
avoid that window, submit the **replacement `witness_set` together with (or
immediately after) the `witness_revocation`**, effective from the same boundary,
so the next STH is cosigned by a full, valid circle.

## 5. Operator ceremony (CLI)

Single-key (root holder signs directly):

```
node axr-key-succession.js revoke-witness <root-priv.pem> \
  --log-id <id> (--revoked <witness-pub.pem> | --revoked-fingerprint sha256:<hex>) \
  --revoked-at <tree_size> [--reason text] > witness-revocation.json
```

Quorum (M-of-N, signers on separate machines), reusing the 0.6 ceremony:

```
node axr-key-succession.js body witness-revocation --log-id <id> \
  (--revoked <witness-pub.pem> | --revoked-fingerprint sha256:<hex>) --revoked-at <n> > body.json
node axr-key-succession.js sign body.json signer1-priv.pem > part1.json   # per signer
node axr-key-succession.js assemble body.json part1.json part2.json \
  --verify <trust-root.json> > witness-revocation.json
```

Then add it to the control log (verified before append, self-lockout guard):

```
node axr-key-succession.js control add control.jsonl witness-revocation.json \
  --trust-root <anchor> --log-id <id>
```

`axr-key-succession.js verify witness-revocation.json <anchor>` prints the
human-readable verdict.

## 6. Consumer behaviour and codes

The monitor and both verifiers (`axr-verify.js`, `axr_verify.py`) collect
root-verified `witness_revocation` records from the control log, fold them into
the witness timeline, and apply the two-tier rule per STH:

- `WITNESS_REVOKED` — **new** in 1.1. A revoked witness's cosignature is present
  on an STH at `tree_size ≥ revoked_at_tree_size`. Always a violation; Critical
  (severity 5) in the OCSF mapping. Emitted by monitor and both verifiers.
- A `witness_revocation` that fails root verification (forged/altered) in the
  control log is rejected as `CONTROL_ROOT_MISMATCH` — the same fail-closed path
  as an invalid `witness_set` (an invalid governance record must not anchor, and
  a post-hoc control-log tamper is caught at verify time).
- `UNDER_WITNESSED` and `WITNESS_COSIGNATURE_INVALID` retain their 0.8 meaning;
  a revocation that pushes the valid count below threshold surfaces as
  `UNDER_WITNESSED`.

No flags are added. `--require-witnesses` keeps its 0.8 meaning.

## 7. Threat model notes

- **Revocation-as-DoS:** because the threshold does not shrink, an attacker who
  could forge a revocation could push a log to `UNDER_WITNESSED`. This is why a
  `witness_revocation` must carry a valid root/quorum signature; a forged one is
  `CONTROL_ROOT_MISMATCH`, not an accepted revocation. With a quorum root the
  bar is M independent signers.
- **Same boundary, conflicting intent:** revocations are monotonic per
  fingerprint (earliest boundary wins), so an authorized party cannot weaken an
  existing revocation by issuing a later-boundary one.
- **Witness still cosigning after revocation:** not assumed malicious (the
  witness may not know it was revoked), but its cosignature is non-counting past
  the boundary and its presence raises `WITNESS_REVOKED` so an operator relying
  on a revoked witness is visible.

## 8. Deferred (out of scope for 1.1)

- Per-witness *suspension* (temporary, auto-expiring exclusion) — only permanent
  revocation is defined.
- Wall-clock validity windows for witnesses — `tree_size` remains the only clock
  (consistent with the rest of AXR).
- Witness-initiated self-revocation — revocation is a root/quorum authority act.
