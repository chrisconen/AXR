# Agent Execution Receipt (AXR)

A lightweight protocol for tamper-evident, cryptographically signed execution records of automated workflows and AI agents.

**Current version:** 0.2 — production-tested  
**Status:** Pilot running on one live workflow. Three pre-existing production bugs discovered and fixed because the receipts made them visible.

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

AXR 0.2 is a working pilot. Each gap below is stated honestly.

**Uniform timestamp.** All step receipts in a run share the same timestamp — the moment the generator node runs — because the generator executes once at the end. Per-step timestamps would require each `__axr_input` marker to also record a write time. Not implemented in 0.2.

**`$('NodeName')` fragility.** The generator reads node outputs via `$('NodeName').all()`. This works in the pilot's n8n version (2.8.3), but cross-node access in the task-runner sandbox is not contractually guaranteed across n8n versions.

**Self-declared agent identity.** `agent_id` is a locally assigned string, not a verified credential. There is no central registry.

**No generative step coverage.** The pilot workflow is fully deterministic. Non-deterministic (LLM) steps are supported by the schema (`step.model`, `step.deterministic: false`) but untested.

**Operator-level key protection.** The Ed25519 private key is a PEM file with mode `600`. Not hardware-grade. A customer-facing deployment at scale would need to revisit key management.

---

## Files

| File | Description |
|------|-------------|
| `axr-core.js` | Shared library: canonicalization, SHA-256, Ed25519 sign/verify, `splitAxrInput` |
| `axr-generator.js` | Receipt generator logic, testable outside n8n |
| `axr-n8n-node.js` | Drop-in n8n Code node (self-contained, no external dependencies) |
| `axr-verify.js` | Standalone verifier: `node axr-verify.js receipts.jsonl public-key.pem` |
| `AXR-SPEC-0_2.md` | Full protocol specification |

---

## Scope

AXR 0.2 deliberately has a narrow scope. It does not provide a central agent registry, protection against private-key exfiltration, or reproducibility guarantees for non-deterministic steps. These are higher layers, intentionally excluded so that 0.2 can prove the core mechanism — signed, chained, per-step precise execution records — in isolation.

---

## License

MIT

---

*Protocol designed and built by Conen Digital. Production deployment on ECO Clean HU booking workflow, May 2026.*
