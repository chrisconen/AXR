# Agent Execution Receipt (AXR)

[![CI](https://github.com/chrisconen/AXR/actions/workflows/ci.yml/badge.svg)](https://github.com/chrisconen/AXR/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](package.json)

A lightweight protocol for tamper-evident, cryptographically signed execution records of automated workflows and AI agents.

**Current version:** 0.2 — production-tested  
**Status:** Pilot running on one live workflow. Three pre-existing production bugs discovered and fixed because the receipts made them visible.

### Maturity by layer

AXR ships as one repository spanning several maturity levels. Read a feature's level before depending on it:

| Layer | Version | Maturity |
|-------|---------|----------|
| Core: signing, chaining, per-step `input_hash`, canonicalization, cross-impl parity | 0.2 | **Stable** — production-tested, frozen wire format |
| Anchoring: Merkle batching, Signed Tree Heads, monitor, OTS submission | 0.3 | **Working** — fully tested, OTS Bitcoin proof delegated to `ots verify` |
| Redactable receipts, side-effect attestation, trust root | 0.4 | **Hardening** — tested, evolving; APIs may still change |

The 0.2 wire format is frozen: 0.1/0.2/0.3 logs verify byte-for-byte under the current verifier. New work is additive. Released versions are intended to be cut as git tags (`v0.2.x`, `v0.3.x`, `v0.4.x`); the `main` branch is the integration line. Run `npm test` (or see CI) for the full cross-implementation suite.

---

## The problem

AI agents and automated workflows now perform real economic actions: booking appointments, pricing services, creating calendar events, sending customer communications. The output of these systems is, by default, ephemeral and unprovable.

After the fact, there is no reliable way to answer:

- Which agent did this?
- What did it receive as input?
- What decision did it make, and on what basis?
- Was the record altered afterwards?
- Why was a customer told "no"?

AXR addresses exactly this gap.

---

## What AXR does

AXR produces **tamper-evident, cryptographically signed records** of what an automated workflow did on each execution.

It proves one thing: that a given workflow, on a given input, made a given decision — and that this record has not been modified since.

It is not a workflow builder, not an agent framework, not an observability platform. It is the accountability layer that sits underneath those tools.

### Two receipt types

A **step receipt** records the execution of a single decision-relevant node. A **workflow receipt** ties the step receipts for one run into a signed, chained record.

Only nodes that change state or make a decision receive step receipts. Nodes that merely forward, format, or notify do not.

### Two levels of chaining

Within a workflow run, step receipts chain to each other via `previous_receipt_hash`. The workflow receipt closes the chain with `chain_root_hash`.

Across runs on one agent, workflow receipts chain to each other. Deletion of any receipt breaks the chain. Alteration of any receipt breaks the signature.

### Cryptography

- **Hashing:** SHA-256 with canonical (key-sorted) JSON serialization, so hashes are deterministic and reproducible.
- **Signatures:** Ed25519. Each receipt is signed without its own `signature` field, then the signature is stored back in.
- **Verification:** A standalone Node.js script with zero external dependencies. Exit code `0` = chain valid, `1` = problem found, `2` = usage error.

---

## What 0.2 adds over 0.1

**Per-step input precision.** In 0.1, every step receipt hashed the same normalized payload — the workflow's initial input — as a uniform proxy for each step's actual input. This was documented as a known limitation (§7.1). In 0.2, each marked node attaches a `__axr_input` field to its output declaring exactly what it consumed. The generator reads this marker, hashes the actual step input, and strips the marker before computing `output_hash`.

**Versioning.** Every receipt carries `axr_version`. The verifier branches on this field. 0.1 chains continue to verify under 0.1 rules. A single receipt log containing both 0.1 and 0.2 receipts is verifiable as one continuous chain.

**Honest failure mode.** If a node is missing its `__axr_input` marker, the generator sets `input_hash` to `null` and emits a warning rather than silently substituting a wrong hash. The chain still verifies; the condition is auditable.

---

## What 0.3 adds over 0.2 (in progress)

0.2 proved a record was unmodified *since signing* — but the operator held the only key and the only log, so nothing stopped silent rewriting, backdating, or keeping two divergent logs. 0.3 introduces a party the operator does not control, turning **tamper-evident** into **tamper-detectable**. The honest analogy is Certificate Transparency, not self-signed HTTPS.

**Independent anchoring.** Receipt hashes are batched into an RFC 6962 Merkle tree (byte-compatible with CT/Rekor tooling). At each interval a **Signed Tree Head** is emitted and its root committed to external, append-only backends (OpenTimestamps/Bitcoin, Rekor, RFC 3161). Each receipt gets an **inclusion proof**; successive tree heads are linked by **consistency proofs** that a monitor can check to detect rewriting or forking.

**Generative-step receipts.** A receipt shape for LLM steps that captures model id/fingerprint, parameters, prompt/tool/completion hashes, usage and finish reason — with an explicit *evidentiary-capture-vs-reproducibility* rule, so it is never read as a claim of reproducible AI decisions.

**Out-of-band sidecar.** Anchoring runs *outside* n8n (`axr-anchor.js`), reading the same append-only `receipts.jsonl`. The booking hot path gains zero latency and zero new dependency; a backend outage degrades a receipt to "pending", never failing it. The only mutation to `receipts.jsonl` is the signature-neutral `anchor_ref` write-back.

The full draft lives in `AXR-SPEC-0.3.md`, including an explicit threat model (guarantees G1–G7, non-guarantees N1–N5) and a prior-art map (CT, Sigstore, in-toto/SLSA, C2PA, RFC 3161, OpenTimestamps).

### Anchoring usage (Stage B)

```bash
# local backend (deterministic, offline - for development/CI)
node axr-anchor.js receipts.jsonl private-key.pem --backend local

# OpenTimestamps (Bitcoin anchor; degrades to pending_offline without network)
node axr-anchor.js receipts.jsonl private-key.pem --backend opentimestamps

# verify, now with the anchoring layer
node axr-verify.js receipts.jsonl public-key.pem sth.jsonl anchors.jsonl
```

The verifier branches on `axr_version`: 0.1/0.2 chains stay valid, 0.3 chains additionally get checks 8–12 (generative well-formedness, evidence-graph integrity, inclusion proofs, STH chain + consistency, offline anchor cross-check).

### The Monitor (Stage D)

Anchoring is *latent* protection — it only matters if an independent party actually watches. The Monitor is that party. Unlike the verifier (which checks a log at one instant), the Monitor checks a log **over time and across views**: it keeps its own retained journal of the Signed Tree Heads it has witnessed, and raises an alarm when a new view contradicts the old one.

```bash
# poll an operator's STH file; the monitor keeps its own journal
node axr-monitor.js poll sth.jsonl public-key.pem \
     --state monitor-state.json --receipts receipts.jsonl --anchors anchors.jsonl

# compare two independent monitors' journals (split-view / equivocation proof)
node axr-monitor.js compare monitor-A.json monitor-B.json
```

What it catches: **EQUIVOCATION** (a different root at an already-witnessed tree size — the operator showed two different trees), **TRUNCATION** (the log shrank), **NON_APPEND_ONLY** (a consistency proof fails — history was rewritten), **ROOT_MISMATCH** (a signed STH whose root does not match the actual receipts), and **BAD_SIGNATURE**. This is what turns guarantees G5/G6 from potential into actual.

### Generative (LLM) steps (Stage C)

A generative node attaches a `__axr_gen` marker to its output alongside `__axr_input`, carrying the full evidence of the model call: model id/fingerprint, parameters, the ordered prompt, tool definitions, the completion, usage, and a `reproducibility` declaration. The 0.3 generator (`generateReceiptsV3`) turns this into a generative step receipt (`step.kind: "generative"`, a `generation` block, `io.decision: null`), and links the downstream deterministic decision to it via the `inputs` evidence graph — so a verifier can check *which* model output the decision consumed.

A generative receipt is **evidence of an invocation, not a reproducible computation** (`reproducibility.level`). The verifier (check 8) enforces well-formedness; the whole pipeline — generator → anchoring sidecar → verifier → monitor — handles generative steps end-to-end (`axr-generative-test.js`).

### Redactable receipts (0.4 prototype) — GDPR erasure vs append-only

Append-only logs and the GDPR right to erasure (Art. 17) appear to conflict: how do you delete personal data from a record whose whole point is that it cannot change? AXR 0.4 resolves this with **field-level salted Merkle commitments**.

Sensitive fields (typically the generative `prompt` / `completion` cleartext) are not signed directly — they are committed through a field-level Merkle tree whose root (`redactable_root`) is signed. The cleartext detail (`redactable`) is excluded from the signature, the chain hash, and the leaf hash. Consequently a field's cleartext can be **erased later** (drop the value and its salt, keep the leaf hash) and:

- the signature stays valid,
- the chain hash is unchanged,
- the already-anchored **leaf hash is unchanged — the Bitcoin/OTS inclusion proof still holds**,
- the commitment still verifies (check 13),
- but the personal data is genuinely gone, and the per-field **salt** makes a redacted field's hash non-brute-forceable.

```js
const { redactable_root, redactable } = core.buildRedactable([
  { path: 'generation.prompt', value: promptMessages }
]);
// ... sign the receipt (redactable detail is excluded from the signature) ...
const erased = core.redactField(receipt, 'generation.prompt'); // GDPR erasure
// erased still verifies; leafHash(erased) === leafHash(receipt)
```

Demonstrated end-to-end in `axr-redactable-test.js`: build → anchor → erase the prompt → the log (with anchors) still verifies, and the cleartext PII is gone. This is the buildable answer to the prompt-retention/GDPR weakness; selective disclosure (SD-JWT/BBS+) and ZKPs are the next layer beyond it.

### Side-effect attestation (0.4) — narrowing N1 ("operator signs its own homework")

Anchoring proves *time and order*, not *truth at signing* (N1). Side-effect attestation binds a receipt's claim to an **external system's own record** so it can be checked independently. A state-changing step (e.g. `Create Booking`) carries a signed `side_effects[]` array:

```json
"side_effects": [
  { "type": "calendar.event.created", "provider": "google-calendar",
    "reference": "evt_abc123", "evidence_hash": "sha256:...", "occurred_at": "..." }
]
```

Two levels:
- **Recheckable** (no attestation): the external reference + a hash of the provider's response let an **auditor independently re-fetch and compare**. Honest framing — not self-proving, but independently checkable.
- **Attested** (provider co-sign): the external service signs the entry with its own key (`attestSideEffect`), cryptographically binding the event to a party **other than the operator**.

`side_effects` is part of the signed receipt (so it is tamper-evident and anchored); the optional provider attestation verifies on top. Verifier check 14; tested in `axr-sideeffect-test.js`.

**Trust root — closing the key→provider bootstrap (§8).** A plain attestation only proves *some* key signed the entry; nothing stops an operator from signing with its own key and calling it `google-calendar`. A **trust root** (`axr-trust-root.js`) is a root-signed, append-resistant allowlist mapping provider names to permitted attestation keys. Supply it with `node axr-verify.js … --trust-root trust-root.json`: an attestation now counts as `attested` only if its key is in the trust root for that provider — otherwise it is downgraded to a problem. The root key is held by a party independent of the operator (auditor, consortium, or published list), which is what makes the binding meaningful. Without a trust root the prior behavior is unchanged (backward compatible). Tested in `axr-trustroot-test.js`.

### Determinism and adversarial testing

The "anyone can verify, in any language" claim rests on **byte-identical canonicalization**. `core.canonicalize` follows RFC 8785 (JCS) key ordering (UTF-16 code units) and ECMAScript number formatting, and **throws** on `NaN`/`Infinity`/`undefined`/`bigint`/non-plain objects rather than silently corrupting them (which `JSON.stringify` would). Cross-implementation byte vectors are pinned in `axr-canonical-test.js`.

`axr-adversarial-test.js` proves the central "tamper-evident" claim systematically: it builds one valid, anchored, generative+redactable log and applies **15 distinct mutations** (body tamper, step deletion, signature swap, STH drop, inclusion-proof tamper, redactable-value tamper, wrong-key resign, evidence-graph break, chain/step_chain tamper, STH tamper, …) — the verifier rejects **all 15**, and the unmodified control passes.

### Cross-implementation verification (the CT-style proof)

The credibility of Certificate Transparency came from *multiple independent implementations agreeing*. AXR ships a second, fully independent verifier in Python (`axr_verify.py`) with **zero external dependencies** — its own canonicalizer, a **pure-Python Ed25519** verifier (RFC 8032, validated against the standard test vectors), and the RFC 6962 Merkle/inclusion/consistency logic.

`axr-crossverify-test.js` proves the two implementations agree:
- **Canonicalization parity**: a battery of values (integers, floats, `1e21`, unicode, emoji, nested objects) canonicalizes to byte-identical output in JS and Python.
- **Agreement on valid**: both verifiers accept the same anchored log (exit 0).
- **Agreement on tampered**: both reject the same mutated logs (exit 1).

```bash
python3 axr_verify.py receipts.jsonl public-key.pem sth.jsonl anchors.jsonl
```

The Python verifier covers the cryptographic core (canonicalization, signatures, chains, Merkle proofs); the niche 0.3/0.4 checks (generative well-formedness, evidence graph, redactable, side-effect) remain the Node verifier's reference scope. The canonicalization byte-vectors (`axr-canonical-test.js`) are the cross-language conformance contract.

---

## Integration into an n8n workflow

The receipt generator is a single n8n **Code node** placed at the end of the workflow, before the response nodes. It reads the outputs of the decision-relevant nodes and generates all receipts in one pass.

Required n8n configuration:

```
NODE_FUNCTION_ALLOW_BUILTIN=crypto,fs
```

### Marking Code nodes (0.2)

Each decision-relevant Code node attaches its actual input before returning:

```javascript
const __axrInput = $input.all().map(i => i.json);
// ... node's own logic unchanged ...
return result.map(item => ({
  json: { ...item.json, __axr_input: __axrInput }
}));
```

### Marking non-Code nodes (Calendar, HTTP, etc.)

Non-Code nodes cannot attach markers themselves. A small `AXR Mark` Code node immediately follows each one:

```javascript
const calIn  = $('<predecessor node name>').all().map(i => i.json);
const calOut = $input.all().map(i => i.json);
return calOut.map((item, idx) => ({
  json: idx === 0 ? { ...item.json, __axr_input: calIn } : item.json
}));
```

The generator reads from the `AXR Mark` node rather than the Calendar node itself.

### Storage

Receipts are appended to an append-only JSON Lines file, one receipt per line. Step receipts for a run are written first, followed by the workflow receipt. The file lives on a bind-mounted host directory so it survives container restarts.

---

## Verification

```bash
node axr-verify.js receipts.jsonl public-key.pem
```

Checks:

1. Every receipt's Ed25519 signature is valid
2. Step chains are continuous within each workflow
3. `chain_root_hash` matches the last step receipt
4. `step_chain` ID list matches the actual step receipts present
5. Workflow receipts are chained to one another across runs
6. Every step receipt has an existing parent workflow receipt

For 0.2 chains, the verifier additionally flags uniform `input_hash` values across steps — a sign that marker propagation has regressed to 0.1 behavior.

### Flags (0.4)

```bash
# CI gate: escalate soft signals (null input_hash, missing redactable detail,
# unknown reproducibility level) from notices to errors
node axr-verify.js receipts.jsonl public-key.pem --strict

# Verify Signed Tree Heads with a key separate from the receipt-signing key
node axr-verify.js receipts.jsonl receipt-pub.pem sth.jsonl anchors.jsonl --sth-key sth-pub.pem

# Bind side-effect attestation to a root-signed provider allowlist (closes N1)
node axr-verify.js receipts.jsonl public-key.pem --trust-root trust-root.json

# Actually query the OpenTimestamps calendars during anchor cross-check
node axr-verify.js receipts.jsonl public-key.pem sth.jsonl anchors.jsonl --online
```

Building a trust root:

```bash
node axr-trust-root.js build providers.json root-priv.pem root-pub.pem > trust-root.json
node axr-trust-root.js verify trust-root.json
```

Upgrading pending OpenTimestamps anchors (calendar-level confirmation; final
Bitcoin proof-of-work is verified by the standard `ots verify` CLI over the
recorded responses, by design):

```bash
node axr-anchor.js upgrade anchors.jsonl
```

### Tests

```bash
npm test          # full suite, including JS<->Python cross-implementation parity
```

---

## Pilot workflow

The protocol is implemented and running in production on a geo-cluster booking workflow for ECO Clean HU (n8n, workflow version 5.0). Six of the workflow's twenty nodes are receipt-bearing:

| Node | Why it earns a receipt |
|------|------------------------|
| Normalize Payload | Converts raw input into decision data |
| Check Day Schedule | Reads calendar state — a decision input |
| The Brain (Logic) | The primary booking decision |
| Fresh Calendar Check | Pre-commit calendar state, may differ from first read |
| Slot Still Free? | Guards against a race condition |
| Create Booking | The only node causing irreversible external state change |

The live receipt log contains 0.1 and 0.2 receipts verifying together as one continuous chain.

---

## What AXR found in production

Three pre-existing bugs in the pilot workflow — all present before AXR was deployed, none caused by it — became visible during 0.2 testing because the receipts contradicted what the workflow was actually doing.

**Bug B.** Every workflow run was firing all three response branches (success email, error response, conflict response) regardless of outcome. A `ZONE_INCOMPATIBLE` rejection still sent a success email. The receipt's `final_status` made the contradiction immediate and auditable. Fix: a `Switch` node routing on `__axr.final_status`.

**Bug C.** Rejection responses sent `{"error": "unknown_error", "message": "<customer's own input>"}` — the rejection reason was lost, and the customer's own message was echoed back as the error. The receipt recorded the correct `final_status` on every run, contradicting what customers received. Fix: a `Build Error Response` Code node assembling the response from the Brain's output directly.

**Bug D.** A recheck conflict produced an HTTP 200 with an empty body. The receipt for the run was a valid 5-step `SLOT_TAKEN_ON_RECHECK` chain, complete and signed. The discrepancy between a correct receipt and an empty response is exactly what AXR is built to surface. Root cause: n8n 2.8.3's behavior when `=`-prefix mode combines with `JSON.stringify` in a Response Body field. Fix: a `Build Conflict Response` Code node, and the Respond node reduced to `{{ JSON.stringify($json) }}` without the `=` prefix.

An accountability layer that produces honest receipts also makes silent failures loud.

---

## Known limitations

AXR 0.2 is a working pilot. Each gap below is stated honestly; the 0.4 hardening pass narrowed several of them (marked).

**Uniform timestamp.** All step receipts in a run share the same timestamp — the moment the generator node runs — because the generator executes once at the end. Per-step timestamps would require each `__axr_input` marker to also record a write time. Still open.

**`$('NodeName')` fragility.** The generator reads node outputs via `$('NodeName').all()`. This works in the pilot's n8n version (2.8.3), but cross-node access in the task-runner sandbox is not contractually guaranteed across n8n versions. Mitigated by the `__axr_input` marker convention, not eliminated.

**Self-declared agent identity.** `agent_id` is a locally assigned string, not a verified credential. There is no central registry. Still open.

**Operator self-attestation of side effects (N1).** *Narrowed in 0.4.* With a `--trust-root` supplied, an attestation only counts when its key is in the independently signed provider allowlist, so an operator can no longer attest as a provider it doesn't control. Without a trust root, the recheckable/attested distinction from 0.4 still applies.

**Operator-level key protection.** *Improved in 0.4.* The verifier supports key-role separation (`--sth-key`): a compromised receipt key cannot forge tree heads, and vice versa. The keys are still PEM files (mode `600`), not hardware-grade; a customer-facing deployment at scale would still revisit key management (HSM/threshold).

**Anchor loop / Bitcoin proof.** *Closed at calendar level in 0.4.* `axr-anchor.js upgrade` and verifier `--online` confirm OTS calendar inclusion; final Bitcoin-block proof-of-work verification is delegated to the standard `ots verify` CLI over the recorded responses, by design (no Bitcoin SPV is reimplemented).

**No generative step coverage in the live pilot.** The pilot workflow is fully deterministic. Non-deterministic (LLM) steps are supported by the schema and tested end-to-end in `axr-generative-test.js`, but not yet exercised on a live workflow.

---

## Files

| File | Description |
|------|-------------|
| `axr-core.js` | Shared library: canonicalization (RFC 8785/JCS, guarded), SHA-256, Ed25519 sign/verify, `splitAxrInput`; **0.3:** RFC 6962 Merkle tree (slice-free index-range), inclusion/consistency proofs, version-aware signing, `chainHash`, `splitAxrGen`, `buildGeneration`; **0.4:** redactable field commitments (`buildRedactable`, `redactField`, `verifyRedactable`), side-effect attestation (`attestSideEffect`, `verifySideEffect`), trust root (`buildTrustRoot`, `verifyTrustRoot`, `trustRootHasKey`), incremental Merkle / MMR (`mmrAppend`, `mmrRoot`, `mmrValid`) |
| `axr-generator.js` | Receipt generator logic, testable outside n8n; **0.3:** `generateReceiptsV3` (marker-driven, handles generative steps + `inputs` evidence graph) |
| `axr-n8n-node.js` | Drop-in n8n Code node (self-contained, no external dependencies) |
| `axr-verify.js` | Standalone verifier (checks 1–14): `node axr-verify.js receipts.jsonl public-key.pem [sth.jsonl] [anchors.jsonl]`; **0.4 flags:** `--strict`, `--sth-key`, `--trust-root`, `--online` |
| `axr_verify.py` | **Independent** zero-dependency Python verifier (own canonicalizer, pure-Python Ed25519, RFC 6962 Merkle) — cross-implementation proof |
| `axr-anchor.js` | **0.3:** anchoring sidecar — Merkle batching, Signed Tree Heads, backend submission (local / OpenTimestamps), `anchor_ref` write-back; **0.4:** `upgrade` subcommand (OTS calendar confirmation) |
| `axr-trust-root.js` | **0.4:** trust-root builder/verifier CLI — root-signed provider key allowlist (`build`, `verify`) |
| `axr-monitor.js` | **0.3:** independent monitor — retained STH journal, equivocation/truncation/rewrite detection (`poll`, `compare`) |
| `axr-test-0.3.js` | **0.3:** Merkle/proof test vectors + end-to-end verifier test |
| `axr-anchor-test.js` | **0.3:** anchoring sidecar end-to-end test (idempotency, incremental anchoring, consistency) |
| `axr-monitor-test.js` | **0.3:** monitor test (equivocation, truncation, root-mismatch, bad signature, journal compare) |
| `axr-generative-test.js` | **0.3:** generative-step end-to-end test (generator → sidecar → verifier → monitor) |
| `axr-redactable-test.js` | **0.4:** redactable-receipts test (build → anchor → GDPR erase → still verifies; tamper-fails) |
| `axr-sideeffect-test.js` | **0.4:** side-effect attestation test (recheckable + provider-attested; tamper-fails) |
| `axr-canonical-test.js` | Canonicalization (RFC 8785/JCS) byte vectors, determinism, and guard tests |
| `axr-adversarial-test.js` | Systematic tamper matrix: 15 mutations of a valid anchored log, all rejected |
| `axr-crossverify-test.js` | Cross-implementation test: JS vs Python canonicalization parity + verifier agreement (valid & tampered) |
| `axr-trustroot-test.js` | **0.4:** trust-root test — N1 closure (self-attested key rejected, real provider key accepted, tamper-proof allowlist, end-to-end `--trust-root`) |
| `axr-strict-test.js` | **0.4:** `--strict` mode test — soft signals pass by default, become errors under strict |
| `axr-keysep-test.js` | **0.4:** key-role separation test — STH key distinct from receipt key (`--sth-key`) |
| `axr-incremental-test.js` | **0.4:** incremental anchoring (MMR) test — root byte-identical to from-scratch (n=1..40), multi-run cache, corrupt-cache rebuild |
| `run-tests.js` | Unified test runner (`npm test`) — runs every suite, aggregates exit code for CI |
| `package.json` | Package metadata, `npm test` wiring, zero runtime dependencies |
| `.github/workflows/ci.yml` | CI matrix (Node 18/20/22 x Python 3.10/3.11/3.12) running the full suite incl. cross-impl parity |
| `LICENSE` | MIT |
| `CHANGELOG.md` | Version history, including the 0.4 hardening pass |
| `AXR-SPEC-0.2.md` | 0.2 protocol specification |
| `AXR-SPEC-0.3.md` | 0.3 draft specification (anchoring, generative steps, threat model, identity); §15 future directions (0.4+) |
| `AXR-SPEC-0.4.md` | 0.4 specification (redactable, side-effect, trust root, key separation, incremental anchoring, strict mode) |
| `SECURITY.md` | Responsible-disclosure policy and supported versions |
| `CONTRIBUTING.md` | Contribution guide (zero-dep, frozen wire format, tests-first) |
| `CODE_OF_CONDUCT.md` | Contributor Covenant 2.1 |
| `COMPLIANCE.md` | Technical-control mapping to EU AI Act Art. 12 / GDPR (informational, not legal advice) |

---

## Scope

AXR 0.2 deliberately has a narrow scope. It does not provide a central agent registry, protection against private-key exfiltration, or reproducibility guarantees for non-deterministic steps. These are higher layers, intentionally excluded so that 0.2 can prove the core mechanism — signed, chained, per-step precise execution records — in isolation.

---

## License

MIT

---

*Protocol designed and built by Conen Digital. Production deployment on ECO Clean HU booking workflow, May 2026.*
