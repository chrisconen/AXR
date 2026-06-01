# Agent Execution Receipt (AXR) — Protocol Specification

**Version:** 0.2
**Status:** Pilot — implemented and running in production on one workflow, with three production bugs discovered and fixed by AXR itself
**Date:** 2026-05-15
**Authors:** Chris Conen (Conen Digital), Claude (CTO, CENTAUR)

---

> **HTTPS made web traffic verifiable. AXR does the same for automated decisions.**

---

## 1. Purpose

AI agents and automated workflows can now perform real economic actions:
booking appointments, pricing services, creating calendar events, sending
customer communications. But the output of these systems is, by default,
**ephemeral and unprovable**. After the fact, there is no reliable way to
answer:

- Which agent did this?
- What did it receive as input?
- What decision did it make, and on what basis?
- Was the record altered afterwards?
- Why was a customer told "no"?

AXR addresses exactly this gap. It is a protocol for producing
**tamper-evident, cryptographically signed records** of what an automated
workflow did on each execution. It is not a chatbot, a workflow builder, or
an automation tool. It is the accountability layer that sits underneath
those tools.

AXR proves one thing: that a given workflow, on a given input, made a given
decision — and that this record has not been modified since. In 0.2, that
proof is also **precise**: each step receipt records the actual input of
that step, not merely the workflow's initial input.

### 1.1 What AXR 0.2 is and is not

AXR 0.2 deliberately has a narrow scope. It does **not** provide:

- A central agent registry or verified agent identity. The `agent_id` is a
  locally assigned, self-declared string.
- Protection against private-key exfiltration. The signing key is protected
  at the same level as the rest of the operator's infrastructure, no higher.
- Reproducibility guarantees for non-deterministic (generative) steps. The
  0.2 pilot still runs on a fully deterministic workflow.

These are higher layers, intentionally excluded so that 0.2 can prove the
core mechanism — signed, chained, **per-step precise** execution records —
in isolation.

### 1.2 What 0.2 adds over 0.1

- **Per-step input precision.** Each step receipt now hashes the actual
  input of *that step*, not a uniform copy of the normalized payload. The
  imprecision known as §7.1 in the 0.1 spec is resolved.
- **A versioning mechanism.** Every receipt carries an `axr_version` field.
  Verifiers branch on this field; 0.1 chains continue to verify, 0.2 chains
  receive 0.2-specific checks.
- **A documented marker convention** (`__axr_input`) for marked nodes to
  declare their actual input.
- **Production lessons.** Three pre-existing workflow bugs were uncovered
  and fixed during 0.2 deployment, all unrelated to AXR itself but
  surfaced because the receipts made them visible. These are documented in
  §8 as evidence of the protocol's practical value.

---

## 2. Core concepts

### 2.1 Receipt

A **receipt** is a signed JSON object recording one unit of execution. There
are two types:

- A **step receipt** records the execution of a single decision-relevant
  node in a workflow.
- A **workflow receipt** records an entire workflow run and ties its step
  receipts together into a chain.

### 2.2 What earns a receipt

A node receives a step receipt if, and only if, it **changes state or makes
a decision**. Nodes that merely forward, format, or notify do not get
receipts. Applying this rule to the ECO Clean HU booking workflow, six of
its now-twenty nodes are receipt-bearing:

| Node | Why it earns a receipt |
|------|------------------------|
| Normalize Payload | Converts raw input into decision data; fixes what the input *was* |
| Check Day Schedule | Reads calendar state — a decision input |
| The Brain (Logic) | The primary decision |
| Fresh Calendar Check | The fresh, pre-commit calendar state — may differ from the first read |
| Slot Still Free? | The confirming decision that guards against a race condition |
| Create Booking | The only node causing an irreversible external state change |

Webhook triggers, HTTP response nodes, email/notification nodes, and pure
branching `IF` nodes are intentionally excluded — they neither decide nor
change business state.

### 2.3 Chain length carries meaning — pilot workflow specifics

A workflow run does not always produce all six step receipts. The number
and composition of receipts in a chain *is* part of the testimony:

- **5 steps** with a `final_status` of `ZONE_INCOMPATIBLE` or `DAY_FULL` —
  the Brain rejected the request. In the pilot workflow there is no branch
  immediately after the Brain, so the calendar-recheck nodes still execute
  even on rejection — they read state but do not act. `Create Booking`
  never runs. The chain proves: a decision was made, no booking occurred.
- **5 steps** with a `final_status` of `SLOT_TAKEN_ON_RECHECK` — the Brain
  approved, but the pre-commit recheck found a conflict. `Create Booking`
  never ran. The chain proves: an approval was issued, a race condition was
  caught before any external action.
- **6 steps** — the run completed through to a confirmed booking. The
  chain ends with `Create Booking`.

**A note on the 0.1 spec.** The 0.1 spec described rejections as 3-step
chains. This was an idealised model that did not match the pilot workflow's
actual structure — in the pilot, the Brain has no immediately-following
branch node, so calendar-recheck nodes run regardless of the decision. The
0.2 spec describes what actually happens. At 5 steps, the chain length
alone no longer fully distinguishes a rejection from a recheck conflict;
`final_status` is the discriminator. This is honest, and it is the cost of
matching reality.

A future workflow refactor could introduce a branch right after the Brain,
producing genuine 3-step rejection chains; the AXR protocol would then
record those naturally. But AXR's purpose is to describe what a workflow
*did*, not to enforce what it *should* do.

---

## 3. Receipt schema

All field names are canonical and in English. AXR 0.2 uses `axr_version`
`"0.2"` on every receipt. 0.1 chains remain readable and verifiable.

### 3.1 Step receipt

```json
{
  "axr_version": "0.2",
  "receipt_type": "step",
  "receipt_id": "uuid",
  "workflow_receipt_id": "uuid of the parent workflow receipt",
  "sequence": 3,
  "timestamp": "2026-05-15T07:13:18.123Z",
  "step": {
    "node_name": "The Brain (Logic)",
    "node_type": "n8n-nodes-base.code",
    "logic_version": "5.0 HU",
    "model": null,
    "deterministic": true
  },
  "io": {
    "input_hash": "sha256:...",
    "output_hash": "sha256:...",
    "input_summary": { "date": "2026-05-19", "duration_minutes": 85, "requested_slot_start": "14:00" },
    "decision": {
      "status": "ZONE_INCOMPATIBLE",
      "available": false,
      "cluster_id": "BALATON",
      "cluster_country": "HU",
      "assigned_slot": null,
      "travel_buffer_applied": null,
      "reason": "DISTANCE_TOO_FAR"
    }
  },
  "approval": null,
  "previous_receipt_hash": "sha256:... (hash of the previous step receipt)",
  "signature": "base64 ed25519 signature of the receipt without the signature field"
}
```

**Field notes (changes from 0.1 in bold):**

- `axr_version` — `"0.2"`. The presence and value of this field govern
  which verification rules apply.
- `sequence` — 1-based position of this step within its workflow chain.
- `step.model` — the exact model identifier when the step invokes an LLM;
  `null` for deterministic steps. In the pilot workflow it is `null`
  everywhere.
- `step.deterministic` — `true` if the step's output is a pure function of
  its input.
- **`io.input_hash`** — SHA-256 of the **actual input of this step**,
  extracted from the node output's `__axr_input` marker (see §5.5). In 0.1
  this was uniformly the hash of the normalized payload; in 0.2 it is
  precise per step. If a step's marker is missing, the field is `null` and
  the generator emits a warning rather than silently using a substitute.
- `io.output_hash` — SHA-256 of the step's output, with the `__axr_input`
  marker stripped before hashing (so the hash represents the business
  output, not the receipt's own scaffolding).
- `io.input_summary` — a structured, human-readable, **non-PII** subset of
  the decision input. For audit, not for proof.
- `io.decision` — populated only for the primary decision node (The Brain).
  It mirrors the node's actual machine output; the receipt records the
  decision, it does not re-interpret it.
- `approval` — reserved. Always `null` in 0.2.
- `previous_receipt_hash` — SHA-256 of the previous step receipt in the
  chain; `null` for the first step.

### 3.2 Workflow receipt

```json
{
  "axr_version": "0.2",
  "receipt_type": "workflow",
  "receipt_id": "uuid",
  "workflow": {
    "workflow_id": "eco-clean-geo-cluster-booking-hu",
    "workflow_version": "5.0",
    "webhook_path": "booking-request-hu",
    "trigger_timestamp": "2026-05-15T07:13:18.123Z",
    "completion_timestamp": "2026-05-15T07:13:18.456Z"
  },
  "actor": {
    "agent_id": "eco-clean-booking-hu",
    "agent_type": "n8n-workflow",
    "operator": "Conen Digital",
    "on_behalf_of": "ECO Clean HU"
  },
  "request": {
    "input_hash": "sha256:... (hash of the raw webhook body)",
    "customer_ref": "sha256:... (hash of name+email+phone, in place of PII)"
  },
  "outcome": {
    "final_status": "ZONE_INCOMPATIBLE",
    "available": false,
    "decision_summary": "Elutasitva: ZONE_INCOMPATIBLE, ok: distance_too_far, zona: BALATON"
  },
  "step_chain": ["uuid", "uuid", "uuid", "uuid", "uuid"],
  "chain_root_hash": "sha256:... (hash of the last step receipt)",
  "approval": null,
  "previous_receipt_hash": "sha256:... (hash of the previous workflow receipt on this agent)",
  "signature": "base64 ed25519 signature"
}
```

**Field notes:** Identical in shape to 0.1. The only changes are that
`axr_version` is `"0.2"` and the `outcome.final_status` field can now
disambiguate rejection-at-5-steps from recheck-conflict-at-5-steps.

---

## 4. Cryptography

### 4.1 Canonical serialization

Unchanged from 0.1. Objects are serialized with keys sorted
lexicographically at every level, arrays in order, scalars as JSON. Both
the generator and the verifier must use identical canonicalization. 0.2
inherits this verbatim.

### 4.2 Hashing

`sha256(value)` produces `"sha256:" + hex(SHA-256(canonicalize(value)))`.
Unchanged from 0.1.

### 4.3 Signing

Ed25519. A receipt is signed by canonicalizing the receipt object **without
the `signature` field**, signing those bytes with the private key, and
storing the base64-encoded signature back into the `signature` field.
Unchanged from 0.1.

### 4.4 Two levels of chaining

Unchanged from 0.1:

1. **Within a workflow run** — step receipts link via
   `previous_receipt_hash`. `chain_root_hash` on the workflow receipt closes
   the chain.
2. **Across runs on one agent** — workflow receipts link via their own
   `previous_receipt_hash`.

### 4.5 Versioning (new in 0.2)

The `axr_version` field declares which verification rules apply to a
receipt. A 0.2-aware verifier:

- Verifies the signature and chain-linkage rules on every receipt
  regardless of version (those rules are unchanged).
- Applies 0.2-specific checks — such as flagging uniform `input_hash`
  values across steps in the same chain (a 0.1 regression) — only on 0.2
  receipts.
- Accepts 0.1 receipts as fully valid under 0.1 rules.

This means a single receipt log containing both 0.1 and 0.2 receipts is
internally consistent and verifiable by a single tool. The pilot's
production log demonstrates this directly: the two original 0.1
workflow receipts (2026-05-14 morning) sit alongside the first 0.2
workflow receipt (2026-05-14 evening) and verify together as one valid
chain.

---

## 5. Integration into an n8n workflow

### 5.1 Placement

Unchanged from 0.1: the receipt generator is a single n8n **Code node**
placed at the end of the workflow, before the response nodes. In the pilot
workflow it sits between the decision/booking branches and the response /
notification branches, fed by a `Switch` node that routes by
`__axr.final_status` (see §8.2).

### 5.2 Node configuration

Unchanged from 0.1:

- Mode: **Run Once for All Items**.
- Language: JavaScript.
- Built-in modules required: `crypto` and `fs`, both listed in the
  `NODE_FUNCTION_ALLOW_BUILTIN` environment variable.

### 5.3 Storage

Unchanged from 0.1. Receipts are appended to an append-only JSON Lines
file, one receipt per line, never modified. The file lives on a
bind-mounted host directory so it survives container restarts. Step
receipts for a run are written first, followed by the workflow receipt.

### 5.4 Key handling

Unchanged from 0.1. Ed25519 private key in a PEM file in the same mounted
directory, file mode `600`. Operator-level protection, not hardware-grade.
A production, customer-facing deployment of AXR at scale would need to
revisit key management.

### 5.5 The `__axr_input` marker convention (new in 0.2)

The 0.1 spec hashed a uniform copy of the normalized payload for every
step, because there was no clean way for a Code-node generator running at
the end of the workflow to retrieve each step's actual input. The 0.2 fix:
**each marked node attaches a `__axr_input` field to its output**,
declaring exactly what it consumed.

Concretely:

- A **Code node** marked for AXR attaches `__axr_input` as a final step
  before returning, populated with the actual decision input it used.
- A **non-Code node** (e.g. `googleCalendar`) is followed by a small
  `AXR Mark` Code node that reads the predecessor's output and attaches
  `__axr_input` to the first item. These markers are inserted explicitly
  in the workflow graph.

The generator reads each marked node's output via `$('NodeName').all()`,
extracts the `__axr_input` for hashing, and strips it before computing
`output_hash` so the receipt records the business output, not the
scaffolding.

If a marker is missing on a node that should have one, the generator emits
a warning into the receipt's `__axr.warnings` array and sets `input_hash`
to `null` for that step. The chain still verifies, but the missing-marker
condition is auditable.

---

## 6. Verification

Verification is performed by a standalone Node.js script with zero external
dependencies. Given a receipts file and a public key, it checks:

1. Every receipt's signature is valid.
2. Step chains are continuous within each workflow.
3. `chain_root_hash` matches the last step receipt.
4. The `step_chain` ID list matches the actual step receipts present.
5. Workflow receipts are chained to one another.
6. Every step receipt has an existing parent workflow receipt.

### 6.1 Version-aware verification (new in 0.2)

The 0.2 verifier additionally:

- Reports the `axr_version` distribution across the log (e.g. `0.1: 13,
  0.2: 24`).
- For 0.2 chains, flags uniform `input_hash` values across multiple steps
  in the same workflow chain as a regression to 0.1 behaviour — if a 0.2
  receipt has the same `input_hash` on every step, something has gone
  wrong with marker propagation.
- For 0.1 chains, accepts uniform `input_hash` as expected behaviour.

The script exits `0` if the chain is fully valid, `1` if any problem is
found, `2` on usage error.

Two distinct attack classes are caught:

- **Alteration** — if a receipt's content is changed, the signature fails
  *and* the hash chain breaks.
- **Deletion** — if a receipt is removed from the middle of a chain, the
  signatures of remaining receipts stay valid, but the hash chain breaks
  at the gap and the `step_chain` ID list no longer matches.

---

## 7. Known limitations

AXR 0.2 is a working pilot, not a finished protocol. Each remaining gap
below is acknowledged honestly. A credible specification states its own
weaknesses.

### 7.1 ~~`input_hash` is imprecise~~ — RESOLVED in 0.2

This was the priority correction for 0.2. Each step receipt now hashes the
actual input of that step, supplied via the `__axr_input` marker convention
(§5.5). The version-aware verifier flags any regression to uniform hashes
on 0.2 chains (§6.1).

### 7.2 `$('NodeName')` fragility

Carried over from 0.1, still partially valid. The generator uses
`$('NodeName').all()` to read marked nodes' outputs. This works in the
pilot's n8n version (2.8.3), but cross-node access in the task-runner
sandbox is not contractually guaranteed across n8n versions. A more
robust future version would not depend on node names at runtime.

### 7.3 Uniform `timestamp`

Carried over from 0.1, unchanged. All step receipts in a run still carry
the same timestamp — the end of the workflow run — because the generator
node runs once at the end. Independent per-step timestamps would require
each marker to also record its own write time, which the 0.2 marker
convention does not yet do.

### 7.4 No central identity, no generative coverage, no key hardening

Unchanged from 0.1. The `agent_id` is self-declared, the pilot workflow
has no generative steps, and key storage is operator-level. These are
deliberate scope exclusions for the 0.x line.

---

## 8. Lessons from production

The 0.2 deployment is notable not only for the protocol changes but for
what it surfaced about the workflow it instruments. Three pre-existing
workflow bugs — all present since the 0.1 era, none caused by AXR — became
visible during 0.2 testing and were fixed. These are documented here
because they are evidence of the protocol's practical value: an
accountability layer that produces honest receipts also makes silent
failures loud.

### 8.1 Bug B — the multi-response failure

**Symptom.** During AXR 0.2 testing, every workflow run was firing all
three response branches — the success email, the error response, and the
conflict response — regardless of the actual outcome. A `ZONE_INCOMPATIBLE`
rejection still resulted in a success admin email.

**Why AXR found it.** Without AXR, the workflow author would only have
noticed if a customer reported a "successful" email for an obviously failed
booking. AXR receipts made the contradiction immediate and auditable: a
receipt with `final_status: "ZONE_INCOMPATIBLE"` cannot coexist with a
successful-booking email going out — the receipt insists on the truth.

**Root cause.** The `AXR Receipt Generator` had a single output edge that
fed into all three response nodes, with no routing. Both the receipt
itself and all three response nodes ran on every execution.

**Fix.** A `Switch` node (`Route by Status`) was inserted after the
generator, routing on `$json.__axr.final_status` to exactly one of the
three response branches:

- `ANCHOR_BOOKING`, `SLOT_AVAILABLE`, `SLOT_ADJUSTED` → success email
- `SLOT_TAKEN_ON_RECHECK` → conflict response
- `ZONE_INCOMPATIBLE`, `DAY_FULL`, fallback → error response

**Verified.** Curl-driven tests against the live production endpoint
confirmed only the correct branch fires per outcome.

### 8.2 Bug C — the Respond Error data-source error

**Symptom.** Even after Bug B was fixed, customers receiving rejections
saw a response body of `{"error": "unknown_error", "message":
"<their own input message>"}` — the rejection reason was lost, and the
customer's own form-message was echoed back as the "error message."

**Why AXR found it.** Same mechanism as Bug B. The workflow ran without
crashing; only the response body was nonsense. AXR receipts recorded the
correct `final_status` (`ZONE_INCOMPATIBLE`, `DAY_FULL`) at every run,
contradicting what the customer actually received.

**Root cause.** The `Respond Error` node's template referenced `$json.error`,
`$json.message`, `$json.details` — but the passthrough data arriving at
the node (via the `AXR Receipt Generator` and `Switch`) did not contain
those fields at the top level. They lived on the Brain's output, not on
the passthrough. The template's `|| "unknown_error"` fallback was firing
on every rejection.

**Fix.** A `Build Error Response` Code node was inserted before
`Respond Error`. It reads from `$('The Brain (Logic)').first().json`
directly, assembles the response object with proper fallbacks for the
truly-unknown case, and passes a clean object onward. The `Respond Error`
node's body was simplified to `{{ JSON.stringify($json) }}` (no `=` prefix
— see §8.4).

**Verified.** A `ZONE_INCOMPATIBLE` curl test produced a response body
containing the actual reason text from the Brain
(`"A Balaton régió nagy kiterjedése miatt..."`), the actual machine code
(`"ZONE_INCOMPATIBLE"`), the actual details (`dayZone: "GYOR_PAPA"`, etc.),
and an actionable suggestion (`SHOW_ALTERNATIVE_DATES`).

### 8.3 Bug D — the Respond Conflict template-engine bug

**Symptom.** A recheck conflict produced an HTTP 200 response with an
empty body. The customer's frontend saw a successful HTTP exchange with
no usable content. The workflow executed correctly internally — only the
final response was empty.

**Why AXR found it.** The AXR receipt for the run was a valid 5-step
`SLOT_TAKEN_ON_RECHECK` chain, complete and signed. The discrepancy
between a perfect receipt and an empty customer response is exactly the
kind of silent failure AXR is built to surface.

**Root cause.** The `Respond Conflict` node's body contained an n8n
template that combined `=` prefix mode with mixed static/expression
fields. In n8n 2.8.3 this combination caused the node to throw
`NodeOperationError: Invalid JSON in 'Response Body' field` internally
while still returning HTTP 200 with no body. The template engine's
behaviour with `JSON.stringify(...)` inside a `=`-prefixed mixed
expression is the underlying brittleness.

**Fix.** Same pattern as Bug C: a `Build Conflict Response` Code node
assembles the response object in JavaScript, and `Respond Conflict` is
reduced to `{{ JSON.stringify($json) }}` **without the `=` prefix**. The
prefix-less form makes n8n treat the body as a string-template containing
a single expression, which it handles cleanly. With prefix, the node
attempts a second JSON parse on the stringified object and fails.

**Verified.** A `SLOT_TAKEN_ON_RECHECK` curl test now produces a
fully-populated response body including a `conflictInfo` object with the
real conflicting event's start, end, summary, and location.

### 8.4 What was learned

Three takeaways from these three bugs:

1. **An accountability layer is also a diagnostic layer.** The receipts'
   only job is to record what happened. But by being honest about what
   happened, they also reveal where the workflow lied to its customers.
2. **Code nodes are more robust than template nodes for response
   assembly.** Both `Respond Error` and `Respond Conflict` now use a
   pattern of: a JS Code node builds the response object explicitly,
   the Respond node simply forwards it. This is less elegant than a
   single template, but it survives n8n version upgrades and is trivially
   debuggable.
3. **A `=`-prefix on n8n `Response Body` expressions is a footgun.** The
   prefix subtly changes how the field is parsed in version 2.8.3,
   especially in combination with `JSON.stringify`. Avoid the prefix on
   Respond-to-Webhook bodies; use prefix-less single expressions instead.

These lessons informed the response-assembly patterns now codified in the
pilot workflow, and would inform any future AXR integration into a
similar workflow.

---

## 9. Status and provenance

AXR 0.2 is implemented and running in production on the ECO Clean HU
geo-cluster booking workflow (`eco-clean-geo-cluster-booking-hu`, workflow
version 5.0). As of this document, the live receipt log contains:

- The two original 0.1 production receipts from 2026-05-14 morning
  (`SLOT_TAKEN_ON_RECHECK` 5 steps, `ANCHOR_BOOKING` 6 steps).
- The first 0.2 production receipt from 2026-05-14 evening
  (`SLOT_AVAILABLE`, 6 steps), generated by a real customer-shaped
  request immediately after the 0.2 cutover.

The standalone version-aware verifier confirms all three workflow receipts
and their seventeen aggregated step receipts as fully valid, with mixed
0.1 and 0.2 versions verifying together as one continuous chain.

The deactivated 0.1 workflow is retained as a rollback point until
2026-05-29, after which it will be removed.

---

## 10. Changelog

### 0.2 — 2026-05-15

- **Added.** `axr_version` field on every receipt; version-aware verifier
  (§4.5, §6.1).
- **Added.** `__axr_input` marker convention for precise per-step input
  hashing (§5.5).
- **Resolved.** §7.1 from 0.1 — `input_hash` is now precise per step.
- **Updated.** §2.3 chain-length model now reflects pilot workflow's
  actual structure (5-step rejection, not 3-step).
- **Documented.** Three pre-existing workflow bugs discovered and fixed
  during deployment, none caused by AXR (§8).

### 0.1 — 2026-05-14

- Initial pilot specification.
- Step + workflow receipts, two-level chaining, Ed25519 signatures,
  SHA-256 hashing, canonical serialization, n8n Code-node integration.

---

*The protocol, the generator, and the verifier were designed and built
collaboratively under the CENTAUR model.*
