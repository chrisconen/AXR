# AXR Production Rollout Runbook

**Status:** operational guide, non-normative. Tooling: `axr-rollout.js`
(`bootstrap`, `preflight`). This walks a running 0.2–0.4 pilot (one operator
key, TOFU pinning) onto the 0.5–0.7 root-anchored model **without losing the
existing log**. The governing risk is **self-lockout**: a wrong trust root or
a genesis key that does not match the actual signer makes every consumer
reject the log. `preflight` exists to catch exactly that before you flip the
switch.

The whole point: 0.5–0.7 are **opt-in and additive**. You can adopt them on a
live log with zero changes to the frozen 0.2 wire format and zero re-signing
of past receipts.

---

## 0. Before you start

- Identify the operator key that signs your STHs (and, if separate, your
  receipts). For a pilot that has **never rotated keys**, this is also the
  **earliest** signer, and it becomes the **genesis** — that keeps your
  existing STHs valid (the genesis is authorized from `tree_size = 0`).
- **If your pilot has already rotated keys** (without a root), the genesis must
  be the **earliest/original** signer, **not** the current one — and you must
  supply a root-signed succession for each historical key change at its
  `tree_size`. Otherwise the STHs signed by later keys fail. `preflight`
  reports `ROTATION_PRESENT` when it sees this; treat it as "the genesis check
  alone is not enough — the full verifier with all governance inputs is the
  proof."
- Decide the **root key custody**: a single root key (simplest) or an M-of-N
  quorum (recommended for anything with real audit stakes — 2-of-3, keys on
  separate machines/custodians). The root key is held by a party **independent
  of the operator** (auditor, consortium, published list); that independence
  is what makes the binding meaningful.
- Keep `receipts.jsonl`, `sth.jsonl`, and `anchors.jsonl` together — they
  verify as one set.

## 1. Bootstrap the trust root (from the keys already in use)

Single-key root:

```bash
node axr-rollout.js bootstrap --log-id axr:agent:v1 \
  --sth-pub current-operator-pub.pem [--receipt-pub current-receipt-pub.pem] \
  --root-priv root-priv.pem --out trust-root.json
```

Quorum root (2-of-3; signs with at least the threshold of the declared keys):

```bash
node axr-rollout.js bootstrap --log-id axr:agent:v1 --sth-pub current-operator-pub.pem \
  --root-privs r1-priv.pem,r2-priv.pem,r3-priv.pem --threshold 2 --out trust-root.json
```

`bootstrap` self-verifies the result before writing. Because the **genesis is
the key already signing**, your existing STHs verify unchanged under the new
trust root — no re-anchoring, no re-signing.

## 2. Preflight — GO / NO-GO before going live

```bash
node axr-rollout.js preflight receipts.jsonl sth.jsonl anchors.jsonl \
  --trust-root trust-root.json --key current-operator-pub.pem \
  [--control control.jsonl] [--monitor-state monitor-state.json] [--log-id axr:agent:v1]
```

Exit 0 = **GO** (no blockers), exit 1 = **NO-GO**. Findings are `blocker` /
`warning` / `ok`, each blocker with a remediation hint.

**`--key` is not optional for a GO.** Preflight will not certify a rollout
without running the authoritative `axr-verify.js` (it emits a `NO_VERIFIER`
blocker otherwise). Supply `--key` **and** the governance inputs your log
actually uses (`--successions` / `--control` / a trust-root chain) — the
config checks are smoke tests; only the full verifier proves timeline coverage
on a rotated log.

Key findings: **`GENESIS_MISMATCH`** (blocker) — the declared genesis does not
sign the earliest STH; every STH would fail, the log is lost. **`GENESIS_SIGNS`**
(ok) — the genesis signs *all* STHs (an unrotated log, safe).
**`ROTATION_PRESENT`** (warning) — later STHs use other keys; the genesis check
alone does not prove safety, the mandatory verifier does.
**`MONITOR_GENESIS_MISMATCH`** (blocker) — a monitor already pinned a different
genesis; a live poll would fail closed with `TRUST_ROOT_CHANGED`.

**Honest scope:** preflight catches the *common* self-lockout and N3/N4 traps
and gates on the full verifier — it is a safety net, not a proof of correct
operation. A truncated `sth.jsonl` or missing governance input can still
mislead the config checks; always pass the complete file set.

## 3. Roll consumers over

Once preflight is GO, point the consumers at the trust root:

```bash
# verifier (rotation-spanning, control-aware)
node axr-verify.js receipts.jsonl genesis-pub.pem sth.jsonl anchors.jsonl \
  --trust-root trust-root.json [--control control.jsonl]

# monitor (pins the genesis trust-root; detects unauthorized key change, withholding)
node axr-monitor.js poll sth.jsonl operator-pub.pem \
  --trust-root trust-root.json [--control control.jsonl]
```

The monitor **pins the genesis hash** on its first poll. From then on a
substituted trust-root chain is `TRUST_ROOT_CHANGED` (fail-closed). Run the
monitor as a party **other than the operator** (N4) — the anti-tampering
guarantees are only real with an independent monitor.

## 4. Key rotation (when the time comes)

1. Authorize the successor: `axr-key-succession build … --effective-from <N>`
   (or the `body`/`sign`/`assemble` ceremony for a quorum root).
2. Distribute it: append to the control log
   (`axr-key-succession control add …`) so the rotation is anchored in-log
   (withholding-proof), and/or let the successor's first STH embed it
   (`axr-anchor … --succession …`).
3. The successor signs STHs from `tree_size >= N`; the monitor reports
   `KEY_ROTATED_AUTHORIZED` (a notice, not an alarm).

**Migration duty after a root rotation:** consumers verify against the
*effective* (chain-tail) root, so any still-relevant succession/revocation
must be **re-issued under the new quorum**. Skipping this is self-lockout —
`preflight` will flag it.

## 5. Going further (optional)

- **Control log** (0.7): channel all governance records through `control.jsonl`
  and commit to it (`axr-anchor … --control … --control-trust-root …`). Closes
  withholding/absorption. Once any STH commits, **every later STH must commit**
  — do not drop the `--control` flag mid-stream (that is `CONTROL_DOWNGRADE`).
- **Compliance report** for an auditor: `axr-report.js … --out report.html`.

## 6. Common self-lockout traps (all caught by `preflight`)

| Trap | Finding | Fix |
|---|---|---|
| Genesis key ≠ earliest STH signer | `GENESIS_MISMATCH` (blocker) | Bootstrap with the earliest signing key |
| Rotated pilot, genesis-only check | `ROTATION_PRESENT` (warning) | Supply full governance inputs; rely on the verifier |
| No verifier run (no `--key`) | `NO_VERIFIER` (blocker) | Pass `--key` + governance inputs |
| Monitor already pinned a different genesis | `MONITOR_GENESIS_MISMATCH` (blocker) | Reuse the pinned genesis, or clear the journal in a deliberate migration |
| Trust root tampered/invalid | `TRUST_ROOT_INVALID` (blocker) | Re-bootstrap |
| STHs commit control but log not shipped | `CONTROL_WITHHELD` (blocker) | Ship `control.jsonl`; keep committing |
| Only `local` anchor | `LOCAL_ANCHOR_ONLY` (warning) | Add an independent backend (OpenTimestamps) |
| No independent monitor | `NO_MONITOR` (warning) | Run a monitor as a non-operator party |
| Quorum threshold = 1 | `QUORUM_THRESHOLD_1` (warning) | Raise threshold (2-of-3) |

---

*See `AXR-SPEC-0.5.md`–`AXR-SPEC-0.7.md` for the protocol detail, and
`COMPLIANCE.md` for the control mapping behind the compliance report.*
