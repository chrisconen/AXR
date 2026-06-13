# AXR JavaScript SDK — the stable library surface

AXR has always been usable from the command line (`bin/`). As of **1.2** it is
also a **library with a frozen public surface**: `require('axr')` (or
`require('./index.js')` in-repo) returns one documented entry point whose names
and shapes are stable for the 1.x series.

```js
const axr = require('axr');

// sign and verify a receipt
receipt.signature = axr.sign(receipt, privateKeyPem);   // alias of core.signReceipt
const ok = axr.verifyReceipt(receipt, publicKeyPem);    // true / false

// hashes and canonical bytes (RFC 8785 / JCS, sorted keys, no whitespace)
const h = axr.sha256(value);
const bytes = axr.canonicalize(value);
```

Zero runtime dependencies (Node's built-in `crypto` only); Node ≥ 18.

## Stability policy (1.x)

- Everything documented here is **frozen for 1.x**: the listed top-level names
  and namespace functions will not be renamed, removed, or have their call
  shape changed within the 1.x series.
- The surface may grow **additively** (new names appear) in minor releases.
- Internal helpers reachable through a namespace object but **not listed here**
  are not part of the frozen surface and may change.
- The wire format, canonicalization, CLI flags, and exit codes are frozen
  separately by `AXR-SPEC-1.0.md`; this document freezes only the **JS API**.
- `axr-sdk-surface-test.js` pins this surface: a rename or removal turns it red.

## Top-level convenience

| Name | Shape | Notes |
|---|---|---|
| `version` | string | the package version |
| `canonicalize(value)` | → string | deterministic JSON (sorted keys, no whitespace) |
| `sha256(value)` | → `"sha256:<hex>"` | hash of the canonical bytes |
| `signReceipt(obj, privPem)` / `sign(...)` | → base64 | Ed25519 over the signable part |
| `verifyReceipt(obj, pubPem)` | → boolean | single-receipt signature check |
| `verify(opts)` | → Promise | full-log verification (async); see below |
| `keyFingerprint(pem)` | → `"sha256:<hex>"` | PEM-body fingerprint |

The full `core` surface is also spread at top level for backward compatibility
with the pre-1.2 `main` (`require('axr').merkleRoot`, etc.).

## Namespaces

### `axr.core` — primitives
`canonicalize`, `sha256`, `signReceipt`, `verifyReceipt`, `chainHash`,
`signablePart`, `merkleRoot`, `merkleRootFromLeaves`, `inclusionProof`,
`verifyInclusion`, `consistencyProof`, `verifyConsistency`, `mmrAppend`,
`mmrRoot`, `buildTrustRoot`, `verifyTrustRoot`, `buildRedactable`, `redactField`,
`verifyRedactable`, `attestSideEffect`, `verifySideEffect`.

### `axr.governance` — key & witness lifecycle (axr-succession)
Trust root: `buildTrustRoot`, `buildQuorumTrustRoot`, `verifyTrustRoot`,
`verifyTrustRootChain`, `trustRootMode`, `keyFingerprint`.
Key succession/revocation: `buildKeySuccession`, `verifyKeySuccession`,
`buildKeyRevocation`, `verifyKeyRevocation`, `buildKeyTimeline`, `keyAtTreeSize`.
Witnesses (0.8/1.1): `buildWitnessSet`, `verifyWitnessSet`,
`buildWitnessTimeline`, `witnessAt`, `cosignWitness`,
`assembleWitnessCosignatures`, `verifyWitnessCosignatures`,
`buildWitnessRevocation`, `verifyWitnessRevocation`, `revokedWitnessesAt`
(1.1, permanent), and `buildWitnessSuspension`, `verifyWitnessSuspension`,
`suspendedWitnessesAt` (1.4, temporary `[from, until)` windows).
(Quorum variants `buildQuorum*` are present for each governance record.)

### `axr.anchor` — RFC 6962 anchoring
`runAnchor(opts)` (append leaves, emit a signed STH, commit the control log),
`runUpgrade(opts)`.

### `axr.monitor` — equivocation detection (programmatic verification)
`pollMonitor(opts)` → `{ ok, violations, notices }`. This is the recommended
**programmatic** integrity check over an STH stream (signatures, append-only,
split-view, governance, witnesses). `compareJournals(a, b)`.

### `axr.control` — control log (0.7) + partial disclosure (1.5)
`verifyControlRecord`, `verifyControlLog`, `controlRoot`, `checkSthCommitment`,
`checkControlConsistency`, and (1.5) `buildControlDisclosure` /
`verifyControlDisclosure` — prove one governance record is committed in the
control tree (RFC 6962 inclusion against the STH's `control_root_hash`) without
revealing the rest of the log.

### `axr.ocsf`, `axr.report`, `axr.generator`, `axr.journalReceipts`, `axr.webhook`
SIEM export (`toDetectionFindings`), human-readable compliance report
(`buildReportModel` / `renderHtml` / `renderJson`), reference receipt generation,
the dogfooding journal→receipt primitive (`buildJournalReceipts`), and
best-effort detection delivery (`deliver`).

## Full-log verification — `axr.verify()` (async)

`axr.verify(opts)` runs the **canonical verifier** over a whole log and returns a
structured verdict. It is **async** (full-log verification is an I/O — and, with
`online`, network — operation) and **never diverges from the CLI**: it invokes
the same canonical verifier and derives `ok` from the frozen exit-code contract
(`AXR-SPEC-1.0.md`: 0 = valid, 1 = tampered/invalid, 2 = usage/IO error).

```js
const r = await axr.verify({
  receipts: 'receipts.jsonl',           // required (path)
  publicKey: 'pub.pem',                 // required (path)
  sth: 'sth.jsonl',                     // optional
  anchors: 'anchors.jsonl',             // optional
  trustRoot: 'trust-root.json',         // optional
  control: 'control.jsonl',             // optional
  successions: 'succ.jsonl', revocations: 'rev.jsonl', sthKey: 'sth.pem',
  logId: 'axr:agent:v1',
  strict: false, online: false, requireWitnesses: false
});
// r = { ok, exitCode, problems: [...], notices: [...], output }
//   ok / exitCode  — from the frozen exit-code contract (authoritative)
//   problems/notices — best-effort lines parsed from the verifier report
//                      (human-readable; the text format is NOT frozen)
//   output         — the verifier's full stdout+stderr
```

`opts.receipts` and `opts.publicKey` are required (the call rejects otherwise);
a spawn failure (e.g. no `node`) rejects. For **in-memory** / per-record checks
without a child process, use `axr.core.verifyReceipt` and `axr.monitor.pollMonitor`
directly. The Python mirror `axr_verify.py` remains available as a CLI.

## Example: build and verify a witness revocation

```js
const axr = require('axr');

const rev = axr.governance.buildWitnessRevocation(
  { log_id: 'axr:agent:v1', revoked_fingerprint: fp, revoked_at_tree_size: 1200 },
  rootPrivatePem);

if (axr.governance.verifyWitnessRevocation(rev, trustRoot).ok) {
  // distribute via the control log; consumers apply it from tree_size 1200
}
```
