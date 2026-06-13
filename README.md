# Agent Execution Receipt (AXR)

[![CI](https://github.com/chrisconen/AXR/actions/workflows/ci.yml/badge.svg)](https://github.com/chrisconen/AXR/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](package.json)

A lightweight protocol for tamper-evident, cryptographically signed execution records of automated workflows and AI agents.

**Current version:** 0.8.0 (package) — the production pilot writes the frozen **0.2.1 wire format** with hourly anchoring
**Status:** Pilot running on one live workflow with **hourly Merkle anchoring and STH key separation in production** since June 2026. Four pre-existing production bugs discovered and fixed because the receipts made them visible — plus two bugs AXR found in itself before they could reach the live log (see below).

### Maturity by layer

AXR ships as one repository spanning several maturity levels. Read a feature's level before depending on it:

| Layer | Version | Maturity |
|-------|---------|----------|
| Core: signing, chaining, per-step `input_hash`, canonicalization, cross-impl parity | 0.2.1 | **Stable** — production-tested, frozen wire format; hardened n8n node (guarded canonicalizer, HMAC `customer_ref`, fail-open, `logic_hash`) |
| Anchoring: Merkle batching, Signed Tree Heads, monitor, OTS submission | 0.3 | **Deployed** — hourly anchoring cron live in production (local backend; OpenTimestamps switch planned), separate STH key; OTS Bitcoin proof delegated to `ots verify` |
| Redactable receipts, side-effect attestation, trust root | 0.4 | **Hardening** — tested, evolving; APIs may still change |
| Key succession: root-anchored key rotation (sidecar, monitor, both verifiers, CLI) | 0.5 | **New** — tested incl. cross-impl parity and multi-agent adversarial review; not yet exercised by the production pilot |
| SIEM export: OCSF Detection Finding mapping + generic webhook | 0.6 | **New** — OCSF-shaped output (not formally certified), best-effort delivery by design |
| Root-lifecycle hardening: quorum root (M-of-N), root rotation/recovery, revocation, ceremony CLI | 0.6 | **New** — tested incl. cross-impl parity; quorum policy is part of the threat model (see spec §2.3) |
| Control log: in-log, anchored distribution of governance records (STH commitment, withholding/downgrade detection) | 0.7 | **New** — tested incl. cross-impl parity; closes the out-of-band withholding/absorption gap without touching the wire format |
| Witness cosigning: preventive equivocation defence (stateful witnesses gate STH acceptance) | 0.8 | **New** — tested incl. cross-impl parity; an STH is not fully trusted without a threshold of independent witness cosignatures |

The 0.2 wire format is frozen: 0.1/0.2/0.3 logs verify byte-for-byte under the current verifier. New work is additive. Released versions are intended to be cut as git tags (`v0.2.x` … `v0.5.x`); the `main` branch is the integration line. Run `npm test` (or see CI) for the full cross-implementation suite.

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

## What 0.2.1 adds over 0.2 (production hardening)

A same-wire-format hardening pass on the production n8n node, driven by a live audit (June 2026). Existing 0.1/0.2 chains continue byte-for-byte.

**Guarded canonicalizer in the node.** The inline node code had drifted behind `axr-core.js`: it still serialized `NaN`/`Infinity`/`undefined` silently (as `null` or omitted keys) instead of throwing. The node now carries the same explicit guards as the core, so a signature can never cover silently-corrupted semantics.

**HMAC `customer_ref` with a generated pepper.** The plain `sha256(name|email|phone)` pseudonym was dictionary-attackable: anyone holding the log could confirm whether a known person had booked. `customer_ref` is now `HMAC-SHA256` keyed with a secret pepper that bootstraps itself next to the signing key (mode `600`) on first run. New values intentionally do not link to old ones — the old ones were weak.

**Fail-open receipt generation.** The entire AXR block runs inside a try/catch. A missing key or full disk degrades to a loud `__axr.error` on the passthrough — visible in the admin email and as a gap in the chain — but never fails the customer-facing booking. Receipts must never break the business process they attest.

**`logic_hash` — code fingerprints instead of hand-written labels.** Each attested Code node's receipt now carries the SHA-256 of the node's actual source alongside `logic_version`. The companion `axr-workflow-lint.js` extracts versions and fingerprints from the exported workflow JSON, compares them against the generator's constants, and **fails CI on drift** — eliminating the bug class where receipts attest a logic version that is no longer the code running (see Bug E below).

---

## What 0.3 adds over 0.2 — anchoring now live in production

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

### Key succession (0.5) — rotation distinguishable from compromise

0.3/0.4 pinned one operator key per role (TOFU), so a legitimate, scheduled rotation looked exactly like a silent key swap. 0.5 moves the trust anchor to the independent **root key**: genesis keys are declared in the extended trust root (per log, per role `sth`/`receipt`), and every later key is authorized by a **root-signed `key_succession` record**. The only clock is `tree_size` (Merkle position — the operator cannot back-date it); there are deliberately no wall-clock validity windows.

```bash
# 1. authorize the rotation (root key holder)
node axr-key-succession.js build root-priv.pem --log-id axr:agent:v1 --role sth \
  --predecessor old-pub.pem --successor new-pub.pem --effective-from 1200 > succ.json

# 2. the successor's FIRST STH embeds the record (withholding fix - the rotation is in the log itself)
node axr-anchor.js receipts.jsonl new-priv.pem --succession succ.json

# 3. the monitor distinguishes: authorized rotation = notice, anything else = violation
node axr-monitor.js poll sth.jsonl old-pub.pem --trust-root trust-root.json
#   -> KEY_ROTATED_AUTHORIZED (notice)  |  KEY_CHANGED_UNAUTHORIZED (violation)

# 4. both verifiers verify rotation-spanning logs as one continuous log
node axr-verify.js receipts.jsonl genesis-pub.pem sth.jsonl anchors.jsonl \
  --trust-root trust-root.json --successions successions.jsonl
python axr_verify.py ... # same flags, independent implementation
```

The key timeline is predecessor-linked and **fail-closed**: a broken link poisons everything after it (no "self-healing"), and two root-signed successions for the same boundary (a fork) authorize *neither* branch. Without a trust root every tool behaves bit-for-bit as 0.4. Spec: `AXR-SPEC-0.5.md`; tested across five suites including red-team paths (forged root, silent swap, boundary-violating signatures, forks).

### Root-lifecycle hardening (0.6) — the root key's own lifecycle

0.5 concentrated trust in one root key. 0.6 closes that key's lifecycle, all opt-in:

- **Quorum root (M-of-N multi-signature):** the trust root declares `root_keys` + `threshold`; records verify with M distinct Ed25519 signatures over the same canonical body (strictly fingerprint-ordered — enforced). Honest naming: multi-signature, *not* threshold crypto — root compromise becomes quorum compromise, and the spec's quorum-policy section (§2.3) says so. Recommended default: 2-of-3.
- **Root rotation & recovery:** a successor trust root is signed by the *predecessor's* quorum (`predecessor_trust_root_hash` chain). No self-authorizing roots; a 0.5 single-key root migrates to a quorum the same way. The monitor pins the genesis hash — a substituted chain is `TRUST_ROOT_CHANGED`.
- **Revocation:** a root/quorum-signed `key_revocation` retires a key from a tree-size boundary. Three-tier semantics: anchored pre-boundary artifacts stay valid; unproven pre-boundary is fail-closed; post-boundary is `KEY_REVOKED`.
- **Ceremony CLI:** `axr-key-succession body → sign → assemble --verify` — multi-party signing without hand-crafted JSON; `assemble --verify` refuses to emit a record the consumers would reject.

Spec: `AXR-SPEC-0.6.md`; scope decision trail: `AXR-0.6-SCOPE.md`. 92 assertions across five suites with Python cross-impl agreement.

### Control log (0.7) — the key history is itself anchored

0.6 still distributed receipt-role successions and revocations out-of-band, leaving two gaps: an operator could **withhold** governance records (show different consumers different sets) or let an inconvenient revocation be **absorbed** in distribution. 0.7 closes both: governance records live in an append-only `control.jsonl`, and the **STH signed body commits to it** (`control_root_hash` + `control_size`, RFC 6962 over the records). The committed set is fixed at every tree size — withholding and absorption become loud, while the wire format stays untouched (the control log is a separate sidecar file).

```bash
# governance records go in the control log (verified before append)
node axr-key-succession.js control add control.jsonl rec.json --trust-root trust-root.json
# the sidecar commits to it (and fully verifies every record first - invalid governance is never anchored)
node axr-anchor.js receipts.jsonl key.pem --control control.jsonl --control-trust-root trust-root.json
# monitor/verifiers detect withholding, downgrade, rewrite
node axr-monitor.js poll sth.jsonl pub.pem --trust-root trust-root.json --control control.jsonl
node axr-verify.js receipts.jsonl genesis.pem sth.jsonl anchors.jsonl --trust-root trust-root.json --control control.jsonl
```

Codes: `CONTROL_WITHHELD` / `CONTROL_NON_APPEND_ONLY` / `CONTROL_DOWNGRADE` (Critical), `CONTROL_ROOT_MISMATCH` (High), `CONTROL_LAG` (notice — the monitor tolerates one poll cycle of replication lag, the offline verifier is strict immediately). Spec: `AXR-SPEC-0.7.md`. 55 assertions across five suites with Python cross-impl agreement.

### SIEM export (0.5) — OCSF Detection Findings + webhook

Monitor violations and key-lifecycle events map to **OCSF 1.1.0 Detection Finding** shape (`class_uid` 2004): `KEY_CHANGED_UNAUTHORIZED`/equivocation/truncation → Critical, `KEY_ROTATED_AUTHORIZED` → Informational, unknown violation codes → High (fail-closed). Finding uids are deterministic for SIEM-side dedup; AXR specifics travel under `unmapped.axr`. Honest boundary: OCSF-*shaped*, not formally certified.

```bash
node axr-monitor.js poll sth.jsonl pub.pem --ocsf-out findings.jsonl   # or '-' for stdout
node axr-monitor.js poll sth.jsonl pub.pem --webhook https://siem.example/hook \
  --webhook-token-file token.txt   # or AXR_WEBHOOK_TOKEN env
```

Delivery is **best-effort by design**: a dead SIEM endpoint can neither silence the monitor nor fail a consistent log — the exit code is always the detection result.

### Production rollout — onboarding a running pilot safely

0.5–0.7 are opt-in and additive: a live 0.2–0.4 pilot (one key, TOFU) can adopt root-anchoring **without re-signing or re-anchoring** anything. `axr-rollout.js` makes that safe.

```bash
# 1. bootstrap a trust root from the key ALREADY signing your log (genesis = current signer)
node axr-rollout.js bootstrap --log-id axr:agent:v1 --sth-pub op-pub.pem \
  --root-priv root-priv.pem --out trust-root.json

# 2. GO / NO-GO readiness check BEFORE flipping the switch
node axr-rollout.js preflight receipts.jsonl sth.jsonl anchors.jsonl \
  --trust-root trust-root.json --key op-pub.pem
```

The governing risk is **self-lockout** — a genesis key that does not match the actual signer makes every consumer reject the log. Preflight's `GENESIS_SIGNS` / `GENESIS_MISMATCH` finding catches exactly that, alongside an invalid trust root, a committing STH with no control log shipped, and warnings for local-only anchoring, no independent monitor, or a degenerate quorum. It also embeds the authoritative `axr-verify.js` verdict. Full migration order and the trap table are in `ROLLOUT.md`.

### Witness cosigning (0.8) — preventive equivocation defence

The 0.3 Monitor detects a split view *after the fact*. 0.8 makes the defence **preventive at the acceptance gate**: an STH is not fully trusted until a threshold of independent **witnesses** have cosigned it (the transparency-log pattern — CT 2.0, Sigsum). The witness circle is a root/quorum-signed `witness_set` record in the control log (operational lifecycle, not the trust root).

This only works because the witness is **stateful**: `axr-witness sign` refuses to cosign a non-append-only STH (smaller `tree_size` = truncation; same size, different root = equivocation), so an operator cannot collect a threshold of cosignatures on a divergent branch.

```bash
# a witness cosigns a published STH (stateful: refuses equivocation/truncation)
node axr-witness.js sign sth.jsonl witness-priv.pem --state witness-state.json
# consumers gate on the threshold; strict transparency is opt-in
node axr-verify.js receipts.jsonl pub.pem sth.jsonl anchors.jsonl \
  --trust-root trust-root.json --control control.jsonl --require-witnesses
```

`WITNESS_COSIGNATURE_INVALID` (undeclared/invalid cosignature) and `WITNESS_SET_AMBIGUOUS` (conflicting policy) are always violations; `UNDER_WITNESSED` (below threshold) is a notice by default, a violation under `--require-witnesses` — so a live witness-less pilot is not broken on upgrade. Spec: `AXR-SPEC-0.8.md`. 42 assertions with Python cross-impl agreement. (Trust boundary: the witness's state store must be durable and non-rollbackable — see spec §5.)

### Compliance Report Generator — the auditor's view

An auditor does not read JSONL and Merkle trees at the command line. `axr-report.js` turns a log into a self-contained, human-auditable **HTML** (or JSON) report: log overview, signature & anchoring integrity, the **key-governance timeline** (genesis → successions → revocations, the active key per role, authorized/revoked flags), the control-log commitment summary, privacy/side-effect counts, and an **EU AI Act Art.12 / GDPR control mapping** (drawn from COMPLIANCE.md, with the honest caveats).

```bash
node axr-report.js receipts.jsonl pub.pem sth.jsonl anchors.jsonl \
  --trust-root trust-root.json --control control.jsonl --out report.html
```

Honest framing, per the project's doctrine: the report is a **view over the verifier's verdict**, not a replacement for it. The PASS/FAIL banner is the exit code of `axr-verify.js` run with the same flags, faithfully reported; the report asserts nothing it did not check, restates the N1/N2/N4 limits, and is reproducible (same inputs → same report). A test cross-checks that the report's verdict matches the verifier on both a valid and a tampered log.

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

The protocol is implemented and running in production on a geo-cluster booking workflow for ECO Clean HU (n8n, workflow version 5.1, node v0.2.1). Six of the workflow's twenty nodes are receipt-bearing, and since June 2026 the receipt log is **anchored hourly** by the out-of-band sidecar (227+ receipts in the Merkle tree at the time of writing), with the STH signed by a **separate key** (`--sth-key` verification path) in both verifiers:

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

Four pre-existing bugs in the pilot workflow — all present before AXR was deployed, none caused by it — became visible because the receipts (or the tooling around them) contradicted what the workflow was actually doing.

**Bug B.** Every workflow run was firing all three response branches (success email, error response, conflict response) regardless of outcome. A `ZONE_INCOMPATIBLE` rejection still sent a success email. The receipt's `final_status` made the contradiction immediate and auditable. Fix: a `Switch` node routing on `__axr.final_status`.

**Bug C.** Rejection responses sent `{"error": "unknown_error", "message": "<customer's own input>"}` — the rejection reason was lost, and the customer's own message was echoed back as the error. The receipt recorded the correct `final_status` on every run, contradicting what customers received. Fix: a `Build Error Response` Code node assembling the response from the Brain's output directly.

**Bug D.** A recheck conflict produced an HTTP 200 with an empty body. The receipt for the run was a valid 5-step `SLOT_TAKEN_ON_RECHECK` chain, complete and signed. The discrepancy between a correct receipt and an empty response is exactly what AXR is built to surface. Root cause: n8n 2.8.3's behavior when `=`-prefix mode combines with `JSON.stringify` in a Response Body field. Fix: a `Build Conflict Response` Code node, and the Respond node reduced to `{{ JSON.stringify($json) }}` without the `=` prefix.

**Bug E.** After a routine geo-zoning bugfix bumped the Brain logic to v5.1, every receipt kept attesting `logic_version: '5.0'` — cryptographically valid signatures over a false claim about which code made the decision. A second, previously unknown mismatch (Normalize v3.3 attested as 3.2) surfaced in the same scan. Caught by the new `axr-workflow-lint.js`; fixed by code-hash fingerprints (`logic_hash`) in every receipt plus a CI gate that fails on drift. Lesson: version labels are testimony; code hashes are evidence.

An accountability layer that produces honest receipts also makes silent failures loud.

### Bugs AXR found in itself

The same honesty applies inward. Two defects in AXR's own tooling were caught by a sandbox dry-run of the anchoring rollout — before they could touch the production log:

**Cross-version anchoring broke legacy signatures.** `signablePart` stripped `anchor_ref` from the signed portion only for 0.3+ receipts, while the anchoring sidecar writes `anchor_ref` back into *every* newly covered receipt — including legacy 0.1/0.2 ones. First production run of the sidecar would have rendered the entire historical chain's signatures invalid (recoverably, but alarmingly). Fix: presence-based stripping in both implementations — `anchor_ref` is by definition written after signing and is never part of any version's signature. Regression-locked in `axr-legacy-anchor-test.js` (anchor a 0.2 log → both verifiers must accept; tamper → both must reject).

**The Python verifier silently ignored `--sth-key`.** Key-role separation existed only in the JS verifier; the cross-implementation suite had never exercised the flag. Under separated keys, the Python verifier rejected every valid STH. Fix: `--sth-key` implemented in `axr_verify.py` with JS-identical semantics, covered by the same regression test.

A dry-run that breaks in a sandbox is a feature. Both fixes shipped before the first production anchor was cut.

---

## Known limitations

AXR 0.2 is a working pilot. Each gap below is stated honestly; the 0.4 hardening pass narrowed several of them (marked).

**Uniform timestamp.** All step receipts in a run share the same timestamp — the moment the generator node runs — because the generator executes once at the end. Per-step timestamps would require each `__axr_input` marker to also record a write time. Still open.

**`$('NodeName')` fragility.** The generator reads node outputs via `$('NodeName').all()`. This works in the pilot's n8n version (2.8.3), but cross-node access in the task-runner sandbox is not contractually guaranteed across n8n versions. Mitigated by the `__axr_input` marker convention, not eliminated.

**Self-declared agent identity.** `agent_id` is a locally assigned string, not a verified credential. There is no central registry. Still open.

**Operator self-attestation of side effects (N1).** *Narrowed in 0.4.* With a `--trust-root` supplied, an attestation only counts when its key is in the independently signed provider allowlist, so an operator can no longer attest as a provider it doesn't control. Without a trust root, the recheckable/attested distinction from 0.4 still applies.

**Operator-level key protection.** *Improved in 0.4.* The verifier supports key-role separation (`--sth-key`): a compromised receipt key cannot forge tree heads, and vice versa. The keys are still PEM files (mode `600`), not hardware-grade; a customer-facing deployment at scale would still revisit key management (HSM/threshold).

**Anchor loop / Bitcoin proof.** *Closed at calendar level in 0.4.* `axr-anchor.js upgrade` and verifier `--online` confirm OTS calendar inclusion; final Bitcoin-block proof-of-work verification is delegated to the standard `ots verify` CLI over the recorded responses, by design (no Bitcoin SPV is reimplemented).

**No generative step coverage in the live pilot.** The pilot workflow is fully deterministic. Non-deterministic (LLM) steps are supported by the schema and tested end-to-end in `axr-generative-test.js`, but not yet exercised on a live workflow. Next planned milestone.

**Monitor independence.** Anchoring is live, but the independent monitor (`axr-monitor.js`) is not yet running at a party outside the operator's infrastructure. Until it does, the anchoring layer's split-view/equivocation detection (G5/G6) remains latent protection. Being deployed.

**Local anchoring backend.** The production sidecar currently uses the deterministic `local` backend. The switch to OpenTimestamps (Bitcoin) is a single flag and is planned once the local cadence has run stably.

---

## Files

| File | Description |
|------|-------------|
| `axr-core.js` | Shared library: canonicalization (RFC 8785/JCS, guarded), SHA-256, Ed25519 sign/verify, `splitAxrInput`; **0.3:** RFC 6962 Merkle tree (slice-free index-range), inclusion/consistency proofs, version-aware signing, `chainHash`, `splitAxrGen`, `buildGeneration`; **0.4:** redactable field commitments (`buildRedactable`, `redactField`, `verifyRedactable`), side-effect attestation (`attestSideEffect`, `verifySideEffect`), trust root (`buildTrustRoot`, `verifyTrustRoot`, `trustRootHasKey`), incremental Merkle / MMR (`mmrAppend`, `mmrRoot`, `mmrValid`) |
| `axr-generator.js` | Receipt generator logic, testable outside n8n; **0.3:** `generateReceiptsV3` (marker-driven, handles generative steps + `inputs` evidence graph) |
| `axr-n8n-node.js` | Drop-in n8n Code node (self-contained, no external dependencies); **0.2.1:** guarded canonicalizer, HMAC `customer_ref` + pepper bootstrap, fail-open, `logic_hash`, `AXR_DIR` env override |
| `axr-workflow-lint.js` | **0.2.1:** CI gate against logic drift — fingerprints every attested node's code (SHA-256) in the exported workflow JSON and fails on mismatch with the generator's `logic_version`/`logic_hash` constants (`--manifest` emits fresh fingerprints) |
| `axr-verify.js` | Standalone verifier (checks 1–15): `node axr-verify.js receipts.jsonl public-key.pem [sth.jsonl] [anchors.jsonl]`; **0.4 flags:** `--strict`, `--sth-key`, `--trust-root`, `--online`; **0.5 flags:** `--successions`, `--log-id` (rotation-spanning verification) |
| `axr_verify.py` | **Independent** zero-dependency Python verifier (own canonicalizer, pure-Python Ed25519, RFC 6962 Merkle) — cross-implementation proof |
| `axr-anchor.js` | **0.3:** anchoring sidecar — Merkle batching, Signed Tree Heads, backend submission (local / OpenTimestamps), `anchor_ref` write-back; **0.4:** `upgrade` subcommand (OTS calendar confirmation) |
| `axr-trust-root.js` | **0.4:** trust-root builder/verifier CLI — root-signed provider key allowlist (`build`, `verify`) |
| `axr-monitor.js` | **0.3:** independent monitor — retained STH journal, equivocation/truncation/rewrite detection (`poll`, `compare`); **0.5:** timeline-based key verification (`--trust-root`, `--successions`), `KEY_ROTATED_AUTHORIZED`/`KEY_CHANGED_UNAUTHORIZED`, OCSF export (`--ocsf-out`), webhook (`--webhook`); **0.7:** control-log consumption (`--control`), `CONTROL_WITHHELD`/`DOWNGRADE`/`NON_APPEND_ONLY`; **0.8:** witness gating (`--require-witnesses`), `WITNESS_COSIGNATURE_INVALID`/`UNDER_WITNESSED` |
| `axr-succession.js` | **0.5:** key-succession module — genesis-bearing trust root, root-signed succession records, predecessor-linked key timeline (transitive authorization, fail-closed forks), `keyAtTreeSize`; **0.6:** quorum primitives (`signQuorumPart`/`assembleQuorum`/`verifyQuorumSigned`), trust-root chains (`buildTrustRootSuccessor`/`verifyTrustRootChain`), revocation (`key_revocation`, `revoked_from`) |
| `axr-key-succession.js` | **0.5:** succession CLI — `build`, `verify`, `fingerprint`; **0.6:** ceremony (`body`/`sign`/`assemble --verify`), `revoke`, chain-capable anchors |
| `axr-control.js` | **0.7:** control-log module — `controlRoot` (RFC 6962 over governance records), `verifyControlLog`, `checkSthCommitment`, `checkControlConsistency` (append-only over the control tree) |
| `axr-witness.js` | **0.8:** witness CLI — stateful `sign` (refuses non-append-only STHs) + `verify`; the witness primitives (`buildWitnessSet`, `buildWitnessTimeline`, `cosignWitness`, `verifyWitnessCosignatures`) live in `axr-succession.js` |
| `axr-report.js` | **Compliance Report Generator** — human-auditable HTML/JSON report from a log: integrity, key-governance timeline, anchoring, EU AI Act Art.12 / GDPR control mapping; the PASS/FAIL banner is the verifier's verdict (a view, not a replacement) |
| `axr-rollout.js` | **Production rollout tooling** — `bootstrap` (trust root from the keys already in use) + `preflight` (GO/NO-GO readiness that catches self-lockout before going live); runbook in `ROLLOUT.md` |
| `axr-ocsf.js` | **0.5:** OCSF 1.1.0 Detection Finding mapping for monitor events — deterministic finding uids, fail-closed severity for unknown violation codes |
| `axr-webhook.js` | **0.5:** generic best-effort webhook delivery (http/https only, retry, never affects detection results) |
| `axr-test-0.3.js` | **0.3:** Merkle/proof test vectors + end-to-end verifier test |
| `axr-anchor-test.js` | **0.3:** anchoring sidecar end-to-end test (idempotency, incremental anchoring, consistency) |
| `axr-monitor-test.js` | **0.3:** monitor test (equivocation, truncation, root-mismatch, bad signature, journal compare) |
| `axr-legacy-anchor-test.js` | **0.2.1 regression:** anchoring a legacy 0.2 log must not break signature verification — both verifiers accept post-anchor, both reject tamper (locks the cross-version `anchor_ref` fix and the Python `--sth-key` path) |
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
| `axr-succession-test.js` | **0.5:** key-timeline test — 35 assertions incl. red-team (forged signature, fingerprint lie, foreign root, broken chain, forks, post-fork continuation) |
| `axr-anchor-succession-test.js` | **0.5:** `embedded_succession` test — backward compat, idempotency, signature+chain coverage, sidecar guards |
| `axr-monitor-succession-test.js` | **0.5:** monitor key-succession test — authorized rotation vs forged/silent swaps, degraded mode, journal extension, chain-hash determinism |
| `axr-verify-succession-test.js` | **0.5:** rotation-spanning verification, **cross-impl** — JS and Python must agree on accept AND reject across rotated-log fixtures |
| `axr-key-succession-cli-test.js` | **0.5:** succession CLI test incl. end-to-end embed via the sidecar |
| `axr-ocsf-test.js` | **0.5:** OCSF mapping test — severity table, structure, deterministic uid, fail-closed unknown codes |
| `axr-webhook-test.js` | **0.6:** webhook test — live test server end-to-end, retry, token via file/env, plaintext warning, exit-code isolation |
| `axr-quorum-test.js` | **0.6:** quorum core test — 2-of-3 build/verify, all fail-closed invariants (M-1, duplicate/undeclared signer, tampered body, unordered set) |
| `axr-quorum-e2e-test.js` | **0.6:** quorum end-to-end — production path through sidecar/monitor/both verifiers, under-quorum rejection |
| `axr-rootrotation-test.js` | **0.6:** trust-root chain test — rotation, migration from single-key, genesis-pin (`TRUST_ROOT_CHANGED`), self-authorizing successor rejected |
| `axr-revocation-test.js` | **0.6:** revocation test — three-tier rule in both verifiers, monitor `KEY_REVOKED`, forged revocation as `REVOCATION_UNAUTHORIZED` |
| `axr-control-test.js` | **0.7:** control core — root, log verification, commitment + append-only checks |
| `axr-anchor-control-test.js` | **0.7:** sidecar commitment — backward compat, empty log, incremental, forged-record/missing-trust-root both throw |
| `axr-monitor-control-test.js` | **0.7:** monitor — `CONTROL_LAG`→`CONTROL_WITHHELD` escalation, `ROOT_MISMATCH`, `NON_APPEND_ONLY`, `DOWNGRADE` |
| `axr-verify-control-test.js` | **0.7:** cross-impl verifier control checks — JS and Python agree on accept AND reject |
| `axr-witness-test.js` | **0.8:** witness core — witness_set build/verify, timeline (ambiguous fail-closed), cosignature volatility, fail-closed cosignature anomalies |
| `axr-witness-cli-test.js` | **0.8:** witness CLI — stateful sign (truncation/equivocation refusal, idempotent, extension), verify (threshold / under-witnessed / anomaly) |
| `axr-witness-e2e-test.js` | **0.8:** cross-impl end-to-end — threshold met, UNDER_WITNESSED (notice/strict), WITNESS_COSIGNATURE_INVALID, WITNESS_SET_AMBIGUOUS; JS and Python agree |
| `axr-report-test.js` | **CRG:** model fields, governance timeline, HTML/JSON render, and the report verdict cross-checked against `axr-verify.js` on valid and tampered logs |
| `run-tests.js` | Unified test runner (`npm test`) — runs every suite, aggregates exit code for CI |
| `package.json` | Package metadata, `npm test` wiring, zero runtime dependencies |
| `.github/workflows/ci.yml` | CI matrix (Node 18/20/22 x Python 3.10/3.11/3.12) running the full suite incl. cross-impl parity |
| `LICENSE` | MIT |
| `CHANGELOG.md` | Version history, including the 0.4 hardening pass |
| `AXR-SPEC-0.2.md` | 0.2 protocol specification |
| `AXR-SPEC-0.3.md` | 0.3 draft specification (anchoring, generative steps, threat model, identity); §15 future directions (0.4+) |
| `AXR-SPEC-0.4.md` | 0.4 specification (redactable, side-effect, trust root, key separation, incremental anchoring, strict mode) |
| `AXR-SPEC-0.5.md` | 0.5 specification (key succession: records, one-clock boundary rule, timeline semantics, embedded succession, monitor codes, verifier check 15) |
| `AXR-SPEC-0.6.md` | 0.6 specification (quorum root + policy threat model, root rotation/recovery chain, revocation three-tier semantics, ceremony CLI) |
| `AXR-SPEC-0.7.md` | 0.7 specification (control log: STH commitment, append-only governance distribution, withholding/downgrade semantics, identity/epoch) |
| `AXR-SPEC-0.8.md` | 0.8 specification (witness cosigning: stateful witnesses, witness_set in the control log, cosignature coverage, UNDER_WITNESSED/ambiguous semantics) |
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
