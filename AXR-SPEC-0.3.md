# Agent Execution Receipt (AXR) — Protocol Specification

**Version:** 0.3
**Status:** Draft — extends the 0.2 pilot (running in production on one
deterministic workflow). 0.3 adds independent anchoring, generative-step
receipts, an explicit threat model, and optional verifiable identity. The
anchoring and generative layers are specified here and implemented against a
reference test vector set; production rollout of the anchoring layer is staged
(see §13).
**Date:** 2026-06-06
**Authors:** Chris Conen (Conen Digital), Claude (CTO, CENTAUR)

---

> **Certificate Transparency made TLS misissuance *detectable* by publishing
> every certificate to append-only logs that anyone can monitor. AXR does the
> same for automated decisions: it does not prove an agent was honest — it
> makes dishonesty, suppression, and backdating *detectable*.**

---

## 0. A correction we owe the reader

The 0.1 and 0.2 specifications carried the tagline *"HTTPS made web traffic
verifiable. AXR does the same for automated decisions."* That analogy was
wrong, and the error mattered.

HTTPS does not derive its trust from a server signing its own traffic. It
derives trust from **a third party** — a Certificate Authority — vouching for
identity, and increasingly from **Certificate Transparency** logs that publish
every issued certificate so that misissuance cannot stay hidden. AXR through
0.2 had *neither* a third party *nor* a public log. It was a server signing its
own traffic and asking to be believed.

0.3 exists to close exactly that gap. The honest analogy is **Certificate
Transparency**, and that is now the tagline. The change is not cosmetic: it
reframes what AXR can and cannot promise, and it is the reason every other
addition in this version exists.

---

## 1. Purpose

AI agents and automated workflows now perform real economic actions: booking
appointments, pricing services, approving or denying customers, sending
communications. The records they produce are by default ephemeral and
unprovable. AXR produces **tamper-evident, cryptographically signed,
independently anchored** records of what an automated workflow did on each
execution.

Through 0.2, AXR proved one thing well: that a given workflow, on a given
input, produced a given decision, and that the record was internally
consistent and unmodified *since signing*. That last clause was the weakness.
Because the operator held the only signing key and the only copy of the log,
nothing prevented the operator from rewriting history, backdating an entry, or
keeping two divergent logs and showing each auditor a different one.

0.3 narrows that gap. It does not — and cannot, by cryptography alone — prove
that an agent told the truth at the moment it signed. What it adds is
**detectability**: an external, append-only anchor that makes deletion,
reordering, backdating, and equivocation observable to an independent party.
This is the same trust model that Certificate Transparency, Sigstore's Rekor,
and Go's checksum database all rely on. AXR is not inventing it; AXR is
applying it to agent decisions.

### 1.1 What AXR 0.3 is and is not

AXR 0.3 **is**:

- A schema for signed per-step and per-workflow execution records.
- A two-level hash-chaining scheme within and across workflow runs (unchanged
  since 0.1).
- A Merkle-tree batching and **external anchoring** scheme that places a
  periodic, signed commitment to the log's contents into one or more
  independent transparency services.
- A scheme for capturing **generative (LLM) steps** as evidence: the exact
  model, parameters, prompt, tool definitions, and completion, each hashed and
  optionally retained.
- An **optional** identity-binding mechanism that ties an `agent_id` to a
  public key via a verifiable, third-party-attestable record.

AXR 0.3 **is not**, and does not claim to be:

- A guarantee that a signed decision was *correct* or *truthful* at signing
  time. Cryptography cannot establish that. AXR establishes that the record
  cannot be silently changed, suppressed, or backdated *afterwards* without
  detection by a monitor.
- Protection against private-key exfiltration. A stolen key can sign valid
  receipts. Anchoring narrows the window — backdating past the most recent
  anchored tree head is detectable — but does not eliminate the risk.
- A reproducibility guarantee for generative steps. 0.3 captures generative
  steps as *evidence*, not as reproducible computations. See §5.4 for the
  precise distinction, which we treat as load-bearing rather than a footnote.
- A central agent registry. Identity binding in 0.3 is optional and federated,
  not a single authority.

### 1.2 What 0.3 adds over 0.2

- **Independent anchoring (the headline change).** Receipt hashes are batched
  into an RFC 6962-style Merkle tree; the tree head is signed and committed to
  one or more external anchors (a Sigstore/Rekor transparency log, an RFC 3161
  timestamp authority, and/or OpenTimestamps/Bitcoin). Each receipt gets an
  **inclusion proof**; successive tree heads are linked by **consistency
  proofs**. §7.
- **Generative-step receipts.** A receipt shape for non-deterministic LLM
  steps that captures model identity, parameters, full prompt and tool
  context, and completion — hashed, with optional content retention and an
  explicit `reproducibility` declaration. §5.
- **An explicit threat model.** Who the adversary is, what AXR protects
  against, and — stated plainly — what it does not. §2.
- **Optional verifiable identity.** A path from a self-declared `agent_id`
  string to a key-bound, third-party-attestable identity, including a keyless
  (OIDC-based) option compatible with Sigstore. §8.
- **A Monitor role.** The independent party whose existence is what turns
  "tamper-evident" into "tamper-*detected*". Without a monitor, anchoring is
  latent; with one, it is active. §7.5.
- **Prior-art alignment.** An explicit map of how AXR relates to Certificate
  Transparency, Sigstore (Rekor/Fulcio/cosign), in-toto/SLSA, C2PA, RFC 3161,
  and OpenTimestamps — so reviewers can see what is borrowed and what, if
  anything, is new. §12.


---

## 2. Threat model

A specification that asks to be trusted must state precisely whom it defends
against and where it gives up. This section is normative.

### 2.1 The asset

The asset is the **set of execution records** — the claim that a specific
agent, on a specific input, produced a specific decision at a specific time,
and the integrity of that set over time (no silent insertion, deletion,
reordering, or backdating).

### 2.2 Adversaries

We distinguish three adversaries by capability.

**A1 — External observer / tamperer.** Can read or modify the receipt log if
it leaks, but does not hold the signing key. *Goal:* alter or forge records.

**A2 — Dishonest operator (retrospective).** Holds the signing key and full
control of the log file and host. Acts *after the fact* — wants to rewrite,
delete, reorder, or backdate history to change what the record says happened.
This is the central adversary AXR 0.3 is designed against, because it is the
one a self-signed log is defenceless against and the one most likely to matter
in a dispute.

**A3 — Dishonest operator (prospective).** Same powers as A2, but acts *at
signing time* — signs a record that misrepresents what the workflow actually
did, in real time, before any anchor exists.

### 2.3 Guarantees

| # | Property | Against | Mechanism |
|---|----------|---------|-----------|
| G1 | Forgery resistance | A1 | Ed25519 signatures (since 0.1) |
| G2 | Tamper evidence | A1, A2 | Signatures + intra/inter-run hash chaining (since 0.1) |
| G3 | Deletion/reordering evidence | A2 | Chain breaks + `step_chain` mismatch (since 0.1); Merkle inclusion proofs (0.3) |
| G4 | **Backdating evidence** | A2 | External anchor timestamp: a receipt cannot be proven to predate the tree head it was anchored under (0.3) |
| G5 | **Append-only / no-silent-rewrite** | A2 | Merkle consistency proofs between successive signed tree heads (0.3) |
| G6 | **Equivocation evidence** | A2 | Anchored tree heads are public; a monitor comparing its view to the operator's detects a split-view (0.3) |
| G7 | Identity assurance (optional) | A1, partially A2/A3 | Key-bound or OIDC-attested `agent_id` (0.3, §8) |

### 2.4 Non-guarantees (stated plainly)

These are not weaknesses we are hiding; they are the boundary of what the
mechanism can do, and naming them is the point of the section.

- **N1 — Truth at signing (A3).** AXR cannot prove a record was *truthful* when
  signed. If an agent signs "I rejected this for reason X" while really
  rejecting for reason Y, every cryptographic check passes. Anchoring makes the
  record *permanent and timely*, not *honest*. Detecting prospective lies
  requires correlating the receipt against independent evidence (the external
  side effect it claims — an email actually sent, a calendar event actually
  created), which is an application-level control, partly addressed by §5.5.
- **N2 — Key theft.** A stolen key signs valid receipts. Anchoring bounds the
  damage in time (an attacker cannot insert a record *before* the last
  anchored, monitored tree head and have it accepted as pre-dating that head),
  but cannot prevent forward forgery until the key is rotated and the
  compromise published.
- **N3 — Pre-anchor window.** A receipt signed but not yet anchored enjoys G1–G3
  but not G4–G6. The exposure window equals the anchoring interval (§7.3). A
  short interval shrinks the window; it never reaches zero.
- **N4 — Liveness of monitoring.** G6 (equivocation) is only *realised* if at
  least one independent monitor actually checks. Anchoring without monitoring
  is potential, not actual, detection. §7.5 makes the monitor a first-class
  role precisely so this dependency is explicit.
- **N5 — Generative reproducibility.** A captured LLM step is evidence of what
  was sent and received; it is not a guarantee the same input reproduces the
  same output. See §5.4.

### 2.5 Trust assumptions

AXR 0.3 assumes: (a) SHA-256 and Ed25519 are sound; (b) at least one external
anchor is itself append-only and independently operated (the operator does not
also control the anchor); (c) at least one honest monitor exists for the
guarantees that depend on monitoring (G6). Assumption (b) is the load-bearing
one: AXR's improvement over 0.2 is exactly the introduction of a party the
operator does not control. If the operator controls every anchor, 0.3 collapses
back to 0.2's guarantees.


---

## 3. Core concepts

### 3.1 Receipt

A signed JSON object recording one unit of execution. Two base types carry
over from 0.1/0.2:

- A **step receipt** records one decision-relevant node. In 0.3 a step receipt
  is either *deterministic* (as before) or *generative* (new, §5).
- A **workflow receipt** records an entire run and ties its step receipts into
  a chain.

0.3 adds two records that live *outside* the per-run chain:

- A **Signed Tree Head (STH)** is a signed commitment to the entire log up to a
  point in time: its size, its Merkle root, and a timestamp. STHs form their
  own chain. §7.2.
- An **anchor record** binds an STH's root hash to an external transparency
  service's response (a Rekor log entry, an RFC 3161 token, an OpenTimestamps
  proof). §7.4.

### 3.2 What earns a receipt

Unchanged in principle: a node earns a step receipt if, and only if, it
**changes state or makes a decision**. Pure forwarding, formatting, branching,
and notification nodes do not. The pilot workflow's six receipt-bearing nodes
(Normalize Payload, Check Day Schedule, The Brain, Fresh Calendar Check, Slot
Still Free?, Create Booking) are unchanged. A generative node — when the pilot
eventually has one — earns a receipt under the same rule, because deciding is
exactly what it does.

### 3.3 What earns an anchor

Every receipt is eligible for anchoring. Anchoring is not per-receipt but
**per-batch**: receipts accumulate into the Merkle tree, and at each anchoring
interval the current tree head is signed and committed externally. A receipt is
"anchored" once an STH that includes it has been externally committed and that
STH's anchor record exists. Until then it is "pending" (threat-model state N3).

### 3.4 The evidence graph

0.3 makes explicit something implicit in 0.2: receipts form a directed graph,
not merely a linear chain. A deterministic decision that consumed the output of
a generative step references that step's `receipt_id` in a new `inputs` field
(§4.1, §5.5). This lets a verifier reconstruct *"the Brain decided Y because the
model produced X"* as a checkable link, not a narrative assertion.

---

## 4. Receipt schema

All field names are canonical and in English. AXR 0.3 uses `axr_version`
`"0.3"`. 0.1 and 0.2 chains remain readable and verifiable; the verifier
branches on `axr_version` (§10).

### 4.1 Step receipt (deterministic)

```json
{
  "axr_version": "0.3",
  "receipt_type": "step",
  "receipt_id": "uuid",
  "workflow_receipt_id": "uuid of the parent workflow receipt",
  "sequence": 3,
  "timestamp": "2026-06-06T07:13:18.123Z",
  "step": {
    "node_name": "The Brain (Logic)",
    "node_type": "n8n-nodes-base.code",
    "logic_version": "5.0 HU",
    "kind": "deterministic",
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
      "reason": "DISTANCE_TOO_FAR"
    }
  },
  "inputs": ["receipt_id of a generative step whose output this step consumed, if any"],
  "approval": null,
  "previous_receipt_hash": "sha256:... (hash of the previous step receipt)",
  "anchor_ref": null,
  "signature": "base64 ed25519 signature of the receipt without the signature and anchor_ref fields"
}
```

**Changes from 0.2 (in bold conceptually):**

- `step.kind` — new explicit discriminator: `"deterministic"` or
  `"generative"`. `step.deterministic` and `step.model` are retained for
  backward-compatible reading but `kind` is authoritative in 0.3.
- `inputs` — new. An array of `receipt_id`s of upstream receipt-bearing steps
  whose output this step consumed. Builds the evidence graph (§3.4). Empty
  array if the step consumes only the raw workflow input.
- `anchor_ref` — new. `null` at signing time; populated *after* anchoring with
  a reference into the anchor index (§7.4). **It is deliberately excluded from
  the signature** (see the signature note below), because it is written after
  the receipt is signed and must not retroactively invalidate the signature.
- `io.input_hash` — per-step precise, as established in 0.2 via the
  `__axr_input` marker (§9.5). Unchanged.

**Signature scope note (important and new in 0.3).** The signature covers the
receipt canonicalized with *both* the `signature` and `anchor_ref` fields
removed. This two-field exclusion is what lets anchoring be a *post-hoc
annotation*: the receipt is signed and chained at run time, then later an
anchor reference is attached without breaking the signature. Verifiers MUST
strip both fields before checking the signature on a 0.3 receipt. (0.1/0.2
receipts strip only `signature`.)

### 4.2 Step receipt (generative)

The generative shape replaces the `io` block's `decision` emphasis with a
`generation` block. Full treatment in §5; the schema is shown there (§5.3) to
keep the model-capture fields beside their semantics.

### 4.3 Workflow receipt

```json
{
  "axr_version": "0.3",
  "receipt_type": "workflow",
  "receipt_id": "uuid",
  "workflow": {
    "workflow_id": "eco-clean-geo-cluster-booking-hu",
    "workflow_version": "5.0",
    "webhook_path": "booking-request-hu",
    "trigger_timestamp": "2026-06-06T07:13:18.123Z",
    "completion_timestamp": "2026-06-06T07:13:18.456Z"
  },
  "actor": {
    "agent_id": "eco-clean-booking-hu",
    "agent_type": "n8n-workflow",
    "operator": "Conen Digital",
    "on_behalf_of": "ECO Clean HU",
    "identity_ref": null
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
  "anchor_ref": null,
  "signature": "base64 ed25519 signature"
}
```

**Changes from 0.2:**

- `actor.identity_ref` — new, optional. `null` for the self-declared mode
  (identical to 0.2 behaviour); otherwise a reference to an identity attestation
  (§8) binding `agent_id` to the signing key.
- `anchor_ref` — new, same semantics and signature-exclusion as §4.1.
- Everything else is shape-identical to 0.2. The 0.2 chain-length semantics
  (§2.3 of the 0.2 spec: 5-step rejection / 5-step recheck-conflict / 6-step
  booking, disambiguated by `final_status`) are unchanged and still accurate.


---

## 5. Generative-step receipts

This is the section that takes AXR from "accountability for deterministic
automations" toward "accountability for AI agents." It is also the section
most prone to overclaiming, so it is written conservatively.

### 5.1 The problem with generative steps

A deterministic step is a pure function: the same input always yields the same
output, so hashing the input and output captures everything. An LLM step is
not pure. The same prompt to the same model can yield different completions
across calls, and the provider may silently update the model behind a stable
name. Therefore a generative receipt **cannot** make the deterministic step's
implicit promise — "given this input_hash, anyone can recompute output_hash."

What it *can* do is capture, completely and tamper-evidently, **the exact
material of one invocation**: what was sent, with what settings, to what model,
and what came back. That is evidence of an event, not a reproducible
computation. AXR 0.3 captures generative steps at this evidentiary level and is
explicit that this is the ceiling.

### 5.2 What is captured

For each generative step:

- **Model identity** — provider, model id string, and (if the provider exposes
  it) a model/system fingerprint or version (e.g. OpenAI's `system_fingerprint`,
  Anthropic's model snapshot suffix). Captured verbatim from the response.
- **Parameters** — temperature, top_p, max_tokens, stop sequences, seed (if
  supported), and any provider-specific decoding settings that affect output.
- **Prompt context** — the full ordered message list (system, user, assistant,
  tool messages), hashed; optionally retained (§5.6).
- **Tool/function context** — the definitions of any tools/functions exposed to
  the model on this call, hashed. Two runs with identical prompts but different
  available tools are different events, and the hash reflects that.
- **Completion** — the model's full response (text and/or tool calls), hashed;
  optionally retained.
- **Usage and termination** — token counts and `finish_reason`
  (`stop` / `length` / `tool_use` / `content_filter` / ...).

### 5.3 Generative step receipt schema

```json
{
  "axr_version": "0.3",
  "receipt_type": "step",
  "receipt_id": "uuid",
  "workflow_receipt_id": "uuid",
  "sequence": 3,
  "timestamp": "2026-06-06T07:13:18.123Z",
  "step": {
    "node_name": "Intent Classifier",
    "node_type": "n8n-nodes-base.openAi",
    "logic_version": "intent-v2",
    "kind": "generative",
    "deterministic": false,
    "model": {
      "provider": "anthropic",
      "id": "claude-sonnet-4-5-20250929",
      "fingerprint": "model-snapshot-string-from-response-or-null",
      "endpoint": "https://api.anthropic.com/v1/messages"
    }
  },
  "generation": {
    "params": {
      "temperature": 0.0,
      "top_p": 1.0,
      "max_tokens": 512,
      "seed": null,
      "stop": []
    },
    "prompt_hash": "sha256:... (canonicalized ordered message list)",
    "tools_hash": "sha256:... (canonicalized tool/function definitions; null if none)",
    "completion_hash": "sha256:... (full model response: text and tool calls)",
    "prompt_ref": "blob://axr/2026-06-06/uuid.prompt.json or null",
    "completion_ref": "blob://axr/2026-06-06/uuid.completion.json or null",
    "usage": { "input_tokens": 734, "output_tokens": 18 },
    "finish_reason": "stop",
    "reproducibility": {
      "level": "best_effort",
      "deterministic_settings": true,
      "notes": "temperature=0 reduces variance but does not guarantee bit-identical output; provider may update the model behind 'id'; fingerprint pins the snapshot only if the provider returns one"
    }
  },
  "io": {
    "input_hash": "sha256:... (the __axr_input marker: what the node consumed)",
    "output_hash": "sha256:... (the node's business output, marker stripped)",
    "input_summary": { "channel": "webform", "lang": "hu" },
    "decision": null
  },
  "inputs": [],
  "approval": null,
  "previous_receipt_hash": "sha256:...",
  "anchor_ref": null,
  "signature": "base64 ed25519 signature (signature + anchor_ref excluded)"
}
```

Notes:

- `io.decision` is `null` on a generative step. A generative step *produces*
  material; a downstream deterministic step *decides* on it and carries the
  `decision`. This separation is deliberate: it keeps the irreducibly
  non-reproducible part (the model call) distinct from the auditable,
  reproducible part (the logic that acts on it). The downstream decision
  references this receipt via its `inputs` array (§5.5).
- `generation.prompt_hash` and `completion_hash` are always present.
  `prompt_ref`/`completion_ref` are present only when content retention is
  enabled (§5.6); when absent, the receipt proves *that* a specific prompt
  produced a specific completion (if you hold the originals to compare), but
  does not itself store them.

### 5.4 Evidentiary capture vs reproducibility (load-bearing)

We state the distinction as a rule, because conflating the two is the most
likely way for AXR to mislead:

> A generative receipt is **evidence that an invocation occurred with specific
> material**. It is **not** a claim that the invocation is reproducible.

Concretely, a verifier holding a generative receipt and the original prompt and
completion (via retention or external storage) can prove:

- the prompt that was sent (matches `prompt_hash`),
- the parameters and model id used,
- the completion that came back (matches `completion_hash`),
- and that none of the above was altered after signing/anchoring.

A verifier **cannot** prove, from the receipt alone, that re-sending the prompt
would reproduce the completion. The `reproducibility` block exists to make this
ceiling machine-readable rather than buried in prose: `level: "best_effort"`
with `deterministic_settings: true` says "we used settings that minimise
variance," and the `notes` field says plainly why even that is not a guarantee.
A future provider offering verifiable, pinned-weights inference could raise
`level` to a stronger value; 0.3 does not assume such a provider exists.

### 5.5 Decision binding (the evidence graph in practice)

When the deterministic Brain consumes the classifier's output, the Brain's step
receipt sets `inputs: ["<classifier receipt_id>"]`. A verifier can then walk:

```
workflow receipt
  └─ step[Intent Classifier] (generative)  →  completion_hash = H_c
        ▲ referenced by
  └─ step[The Brain] (deterministic, decision=...)  inputs=[classifier_id]
```

This converts the claim "the Brain decided X based on what the model said" from
narrative into a checkable graph edge. It does not prove the Brain *correctly*
interpreted the model output (that is N1 territory), but it proves *which*
model output the Brain was handed.

### 5.6 Content retention and PII

Retaining full prompts/completions (`prompt_ref`, `completion_ref`) maximises
evidentiary value but may capture PII. 0.3 specifies three retention modes,
chosen per deployment:

- **`none`** — only hashes stored. Smallest footprint; proves integrity of
  material you independently retain, proves nothing about content you do not.
- **`encrypted`** — full content stored encrypted at rest under a key separate
  from the signing key; refs point to ciphertext. Default recommendation for
  PII-bearing workflows.
- **`plain`** — full content stored in cleartext alongside receipts. Only for
  non-PII or internal workflows.

The retention mode in force is recorded on the workflow receipt
(`request`-adjacent, implementation-defined) so an auditor knows what to expect.
Hashes are computed over the *cleartext* canonical form in all modes, so
integrity verification is identical regardless of retention.


---

## 6. Cryptography

### 6.1 Carried over from 0.1/0.2 (unchanged)

- **Canonical serialization.** Keys sorted lexicographically at every level,
  arrays in order, scalars as JSON. Generator and verifier must canonicalize
  identically.
- **Hashing.** `sha256(value) = "sha256:" + hex(SHA-256(canonicalize(value)))`.
- **Signing.** Ed25519 over the canonicalized receipt with the excluded
  field(s) removed (0.3: `signature` **and** `anchor_ref`; 0.1/0.2:
  `signature` only).
- **Two-level chaining.** Step receipts link via `previous_receipt_hash` and
  close with `chain_root_hash`; workflow receipts link across runs via their
  own `previous_receipt_hash`.

### 6.2 Merkle tree (new in 0.3, RFC 6962 domain separation)

0.3 batches receipts into a Merkle tree following RFC 6962 (the Certificate
Transparency hashing rules), so that AXR's tree math is identical to a format
auditors and existing CT/Rekor tooling already understand. Domain separation
prevents second-preimage attacks between leaves and internal nodes:

```
leaf_hash(receipt)      = SHA-256( 0x00 || canonical_signed_receipt_bytes )
node_hash(left, right)  = SHA-256( 0x01 || left || right )
```

- A receipt's **leaf input** is its fully signed canonical bytes (signature
  included, `anchor_ref` excluded — the anchor reference does not yet exist when
  the leaf is formed).
- The tree is built left-to-right in receipt-append order. For an odd number of
  nodes at a level, the lone node is promoted unchanged (standard RFC 6962
  behaviour), not duplicated.
- The **root hash** of a tree of size *n* is the commitment anchored externally.

Reference (Node.js, zero dependencies):

```js
const crypto = require("crypto");
const H = (...bufs) => crypto.createHash("sha256").update(Buffer.concat(bufs)).digest();
const LEAF = Buffer.from([0x00]);
const NODE = Buffer.from([0x01]);

function leafHash(canonicalReceiptBytes) {
  return H(LEAF, canonicalReceiptBytes);
}

// RFC 6962 root over an array of leaf buffers (the leaves' canonical bytes)
function merkleRoot(leaves) {
  if (leaves.length === 0) return crypto.createHash("sha256").update(Buffer.alloc(0)).digest();
  let level = leaves.map(leafHash);
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) next.push(H(NODE, level[i], level[i + 1]));
      else next.push(level[i]); // promote lone node
    }
    level = next;
  }
  return level[0];
}
```

---

## 7. Transparency log and external anchoring

This is the section that changes what AXR *is*. Everything before it produces a
log the operator could still secretly rewrite. This section makes rewriting
detectable by a party the operator does not control.

### 7.1 Architecture

```
                    appends                       periodically
 workflow runs ───────────────▶  receipts.jsonl ──────────────▶ Merkle tree
   (signed receipts)               (append-only)                    │
                                                                    │ root_hash
                                                                    ▼
                                                          Signed Tree Head (STH)
                                                          { size, root, ts, prev }
                                                                    │
                                  ┌─────────────────────────────────┼───────────────────────────┐
                                  ▼                                  ▼                           ▼
                            Rekor (Sigstore)                 RFC 3161 TSA               OpenTimestamps
                          append-only public log          signed timestamp token       (Bitcoin anchor)
                                  │                                  │                           │
                                  └────────────── anchor records (one per used backend) ─────────┘
                                                                    │
                                                                    ▼
                                                        Monitor(s) watch STHs,
                                                        verify consistency,
                                                        detect equivocation
```

The receipt-writing path is unchanged from 0.2 (synchronous, in the workflow).
Anchoring is an **asynchronous, out-of-band** process so it never blocks a
booking or adds an external dependency to the hot path. A late or failed anchor
degrades a receipt to "pending" (N3); it never breaks the receipt itself.

### 7.2 Signed Tree Head (STH)

At each anchoring interval, the anchoring process computes the current root and
emits an STH:

```json
{
  "axr_version": "0.3",
  "record_type": "sth",
  "log_id": "axr:eco-clean-booking-hu:v1",
  "tree_size": 41,
  "root_hash": "sha256:...",
  "timestamp": "2026-06-06T08:00:00.000Z",
  "previous_sth_hash": "sha256:... (hash of the previous STH; null for the first)",
  "signature": "base64 ed25519 over the STH without signature"
}
```

- `tree_size` is the number of leaves (receipts) committed. It is monotonic.
- STHs form their own hash chain via `previous_sth_hash`, giving the operator's
  own continuity record independent of the external anchors.
- The STH is what gets anchored externally — small, fixed-size, and revealing
  no receipt content (only a root hash).

### 7.3 Anchoring interval

The interval is a deployment parameter trading off N3 exposure-window size
against anchoring cost/rate-limits of the chosen backend. Recommended defaults:

- **Rekor:** every receipt batch up to a small interval (e.g. 1–5 min) — cheap,
  high-resolution timestamps.
- **RFC 3161 TSA:** every 5–15 min.
- **OpenTimestamps/Bitcoin:** hourly or daily — coarse but extremely strong and
  effectively free; the proof matures as Bitcoin blocks confirm.

Using more than one backend is recommended and is the intended configuration:
fast/cheap logs for resolution, a Bitcoin anchor for long-term, jurisdiction-
independent durability. No single backend is a trust singleton.

### 7.4 Anchor records and `anchor_ref`

Each external commitment produces an **anchor record**:

```json
{
  "axr_version": "0.3",
  "record_type": "anchor",
  "sth_root_hash": "sha256:... (the STH root this anchor commits)",
  "tree_size": 41,
  "backend": "rekor",
  "backend_entry": {
    "log_index": 123456789,
    "log_id": "rekor public log id",
    "integrated_time": 1781078400,
    "inclusion_proof": "as returned by the backend",
    "set": "base64 signed entry timestamp (Rekor SET)"
  },
  "retrieved_at": "2026-06-06T08:00:02.000Z"
}
```

After anchoring, each receipt's `anchor_ref` (left `null` at signing) is
populated with a pointer that lets a verifier locate (a) the STH that includes
the receipt, (b) the receipt's **inclusion proof** to that STH's root, and (c)
the anchor record(s) for that STH:

```json
"anchor_ref": {
  "sth_root_hash": "sha256:...",
  "tree_size": 41,
  "leaf_index": 37,
  "inclusion_proof": ["sha256:...", "sha256:...", "sha256:..."],
  "backends": ["rekor", "opentimestamps"]
}
```

Because `anchor_ref` is excluded from the signature (§4.1), writing it after the
fact does not invalidate the receipt — by design.

### 7.5 The Monitor (the role that makes anchoring real)

Anchoring is *latent* detection. It becomes *active* only when an independent
**Monitor** does three things on a schedule:

1. **Fetches** the operator's published STHs and the corresponding anchor
   records.
2. **Verifies consistency** between each successive pair of STHs using an RFC
   6962 consistency proof — proving the later tree is an append-only extension
   of the earlier one, never a rewrite or fork.
3. **Cross-checks** the anchored root against the external backend
   independently (queries Rekor / verifies the OTS proof itself), so it is not
   taking the operator's word for what was anchored.

A monitor that retains the STHs it has seen detects **equivocation** (G6): if
the operator ever shows a different monitor a tree that is inconsistent with
this one, the two monitors' records cannot both be consistent extensions, and
the split is provable. Monitoring can be run by the customer (ECO Clean HU), by
a regulator, by an insurer, or by a neutral third party. AXR 0.3 does not
mandate who — it mandates only that the role *exists and is fillable by someone
other than the operator*, because that is the entire source of the new
guarantees.

### 7.6 What anchoring does and does not buy (honest summary)

- **Buys:** a receipt cannot be silently backdated before its anchored STH
  (G4); the log cannot be silently rewritten or truncated without breaking
  consistency proofs a monitor will catch (G5); two divergent logs cannot both
  survive monitoring (G6); and the Bitcoin anchor specifically buys
  jurisdiction-independent, operator-independent timestamp durability.
- **Does not buy:** truth at signing (N1), protection from a stolen key signing
  *new* valid receipts going forward (N2), or any guarantee at all in the window
  before the first anchor covers a receipt (N3), or anything whatsoever if no
  monitor ever looks (N4).


---

## 8. Identity (optional, federated)

Through 0.2, `agent_id` was a self-declared string with no binding to the
signing key — anyone could write `"agent_id": "eco-clean-booking-hu"` into a
receipt. 0.3 keeps that mode as the zero-config default but adds two stronger,
optional bindings, surfaced through `actor.identity_ref`.

### 8.1 Mode 0 — self-declared (default, unchanged)

`identity_ref: null`. The `agent_id` means exactly what it meant in 0.2: a
label, not a credential. Honest and zero-friction, but provides no defence
against an impersonator who also holds a valid signing key.

### 8.2 Mode 1 — key-bound identity

A one-time, signed **identity attestation** binds an `agent_id` to an Ed25519
public key:

```json
{
  "axr_version": "0.3",
  "record_type": "identity",
  "agent_id": "eco-clean-booking-hu",
  "public_key": "base64 ed25519 public key",
  "operator": "Conen Digital",
  "valid_from": "2026-06-06T00:00:00.000Z",
  "valid_to": null,
  "signature": "base64 self-signature over the attestation without signature"
}
```

The attestation is itself a receipt-shaped record and is **anchored like any
other** (§7). Anchoring an identity attestation is what makes it meaningful: it
pins, at a publicly-attestable time, that this key claimed this `agent_id`. Key
rotation is a new attestation with a fresh `valid_from`; revocation sets
`valid_to`. `actor.identity_ref` on a workflow receipt points to the attestation
in force at signing time.

This is binding-by-transparency, not binding-by-authority: it does not prove the
operator is *entitled* to the name, only that the claim is public, timestamped,
and consistent over time — so a later impersonator's conflicting claim is
detectable.

### 8.3 Mode 2 — keyless / OIDC (Sigstore-compatible)

For deployments that already use Sigstore, AXR receipts may be signed with
short-lived keys issued by **Fulcio** against an OIDC identity (e.g. a workload
identity or a CI identity), with the signing certificate logged in Rekor. In
this mode the "identity" is the OIDC subject, the key is ephemeral, and the
binding is the Fulcio certificate. `actor.identity_ref` points to the Rekor
entry for the signing certificate. This removes long-lived key custody (a
mitigation for N2) at the cost of depending on the Sigstore PKI. 0.3 specifies
the interop shape but does not require it.

---

## 9. Integration into an n8n workflow

### 9.1–9.5 (carried over from 0.2, unchanged)

Placement of the generator Code node at the end of the workflow (§5.1 of 0.2),
node configuration (Run Once for All Items, `crypto`/`fs` built-ins), append-only
JSONL storage on a bind mount, operator-level Ed25519 key handling, and the
`__axr_input` marker convention for per-step input precision all carry over
verbatim. 0.3 adds *around* this path; it does not change it.

### 9.6 The anchoring sidecar (new)

Anchoring runs **outside** n8n as a small sidecar process (a cron job or a
long-lived worker), reading the same bind-mounted `receipts.jsonl`:

1. On each interval, read all receipts since the last STH.
2. Append their leaves to the Merkle tree; compute the new root.
3. Emit and sign an STH (§7.2); append it to `sth.jsonl`.
4. Submit the STH root to each configured backend (Rekor / TSA / OTS); write the
   returned anchor records to `anchors.jsonl`.
5. Write back each newly-covered receipt's `anchor_ref` (the only mutation ever
   made to `receipts.jsonl`, and a signature-neutral one by §4.1).

Keeping anchoring out of n8n means the booking hot path has zero new external
dependencies and zero added latency — a deliberate reliability choice, and the
reason a backend outage degrades anchoring to "pending" rather than failing a
customer booking.

### 9.7 Generative marker (new)

A generative node attaches `__axr_input` exactly as a deterministic node does,
and additionally attaches a `__axr_gen` block carrying the model id, params,
prompt/tools/completion (or their hashes if retention is `none`), usage, and
`finish_reason`. The generator reads `__axr_gen` to populate the `generation`
block (§5.3) and strips it before computing `output_hash`, identically to how it
strips `__axr_input`.

---

## 10. Verification

The verifier remains a standalone Node.js script with zero external
dependencies. Given a receipts file, an STH file, an anchors file, and a public
key, it performs the 0.1/0.2 checks **plus** the 0.3 anchoring checks, branching
on `axr_version` so mixed logs verify as one.

### 10.1 Carried-over checks (0.1/0.2)

1. Every receipt's signature is valid (0.3: strip `signature` *and*
   `anchor_ref`; 0.1/0.2: strip `signature` only).
2. Step chains are continuous within each workflow.
3. `chain_root_hash` matches the last step receipt.
4. `step_chain` ID list matches the step receipts present.
5. Workflow receipts are chained across runs.
6. Every step receipt has an existing parent workflow receipt.
7. (0.2) For 0.2 chains, uniform `input_hash` across steps is flagged as a
   regression; for 0.1 chains it is accepted.

### 10.2 New 0.3 checks

8. **Generative-step well-formedness.** For `step.kind == "generative"`:
   `generation.prompt_hash` and `completion_hash` are present and well-formed;
   `model.id` and `model.provider` are non-null; `io.decision` is `null`;
   `reproducibility.level` is a recognised value.
9. **Evidence-graph integrity.** Every `receipt_id` referenced in any `inputs`
   array exists in the same workflow chain and has an earlier `sequence`.
10. **Inclusion proofs.** For each anchored receipt, recompute the STH root from
    the receipt's leaf, `leaf_index`, and `inclusion_proof`; assert it equals
    `anchor_ref.sth_root_hash` and that an STH with that root and `tree_size`
    exists and is validly signed.
11. **STH chain + consistency.** STHs are validly signed and chained via
    `previous_sth_hash`; for each successive pair, an RFC 6962 consistency proof
    holds (the later tree is an append-only extension of the earlier).
12. **Anchor cross-check (optional, network).** For each anchor record, query
    the backend (Rekor index / verify the OTS proof / validate the RFC 3161
    token) and assert it commits the same root. Skipped in offline mode with an
    explicit `ANCHOR_UNVERIFIED` note rather than a silent pass.

Exit codes: `0` fully valid, `1` any problem, `2` usage error. Anchoring
problems are reported with severity: a broken inclusion or consistency proof is
fatal (`1`); a "pending" (not-yet-anchored) receipt is a warning, not a failure.

### 10.3 Reference: inclusion and consistency proof verification

```js
const crypto = require("crypto");
const H = (...b) => crypto.createHash("sha256").update(Buffer.concat(b)).digest();
const NODE = Buffer.from([0x01]);
const hx = (s) => Buffer.from(s.replace(/^sha256:/, ""), "hex");

// RFC 6962 inclusion proof: recompute root from a leaf hash at `index` in a tree of `size`.
function rootFromInclusionProof(leafHash, index, size, proof) {
  let h = leafHash, i = index, sz = size, p = 0;
  while (sz > 1) {
    if (i % 2 === 1) {                    // right child: sibling is on the left
      h = H(NODE, proof[p++], h);
    } else if (i < sz - 1) {              // left child with a right sibling
      h = H(NODE, h, proof[p++]);
    } // else: lone promoted node, no sibling consumed at this level
    i = Math.floor(i / 2);
    sz = Math.ceil(sz / 2);
  }
  return h;
}

function verifyInclusion(receiptLeafHash, anchorRef, sthRootHex) {
  const proof = anchorRef.inclusion_proof.map(hx);
  const got = rootFromInclusionProof(receiptLeafHash, anchorRef.leaf_index, anchorRef.tree_size, proof);
  return got.equals(hx(sthRootHex));
}
```

The consistency-proof verifier (proving tree size *m* is a prefix of tree size
*n*) follows RFC 6962 §2.1.2 verbatim; it is included in the reference
implementation and omitted here only for length. The point of shipping these as
plain, dependency-free functions is that **any** auditor can run them — and that
they are byte-compatible with Certificate Transparency, so existing CT/Rekor
verifiers validate AXR trees without modification.


---

## 11. Known limitations

AXR 0.3 is a draft extending a working pilot. Naming weaknesses is a feature of
this document, not an apology.

### 11.1 Truth at signing remains out of reach (N1)

No amount of anchoring proves a record was honest when made. This is a hard
limit of any signing scheme, AXR included. The realistic mitigation is
*cross-evidence*: pairing a receipt with an independent trace of the side effect
it claims (an email provider's send log, a calendar API's event id, a payment
processor's reference). 0.3 leaves this to the application; a future version may
specify a "side-effect attestation" record so the claimed effect is itself
captured and anchored.

### 11.2 The pre-anchor window (N3)

A receipt is only protected against backdating *after* an STH covering it is
anchored and monitored. Between signing and anchoring it has 0.2-level
guarantees only. Shortening the interval shrinks but never closes this window.
For high-stakes decisions, a synchronous per-receipt anchor (e.g. a direct Rekor
entry inline) could close it at the cost of hot-path latency and a runtime
external dependency — explicitly rejected for the booking workflow, but a valid
choice elsewhere.

### 11.3 Monitoring is a social, not cryptographic, guarantee (N4)

G5 and G6 are only realised if someone monitors. AXR can make monitoring cheap
and standard, but cannot force it to happen. A deployment with no monitor has
anchoring's *potential* but not its *effect*. This should be stated to any party
relying on AXR receipts.

### 11.4 Generative reproducibility (N5)

Restated from §5.4 because it bears repeating: a generative receipt is evidence
of an invocation, not a reproducible computation. Anyone citing AXR for
"reproducible AI decisions" is overstating it; the correct phrase is "auditable
record of the AI invocation."

### 11.5 `$('NodeName')` fragility

Carried over from 0.1/0.2. The generator reads marked nodes via
`$('NodeName').all()`, which is not contractually guaranteed across n8n
versions. Works in the pilot's 2.8.3. A more robust future version would not
depend on runtime node names.

### 11.6 Uniform per-run timestamp

Carried over. All step receipts in a run share the run's end timestamp because
the generator runs once at the end. Anchoring now provides an *external* time
bound per batch (stronger than the self-asserted per-run timestamp ever was),
but intra-run per-step ordering still rests on `sequence`, not on time.

### 11.7 Key management still operator-grade

The Ed25519 key sits in a mode-`600` PEM on a bind mount (Mode 0/1). Mode 2
(keyless/Sigstore) removes long-lived key custody but adds a PKI dependency.
Hardware-backed keys (HSM/TPM) are compatible with the schema but unspecified
here. N2 stands.

---

## 12. Prior art and how AXR relates to it

AXR's credibility depends on being honest about what it borrows. Almost every
mechanism in 0.3 is taken from an existing, battle-tested system. AXR's
contribution is the *assembly* — applying these to per-step agent decisions in a
workflow tool — not the primitives.

| System | What AXR borrows | How AXR differs |
|--------|------------------|-----------------|
| **Certificate Transparency** (RFC 6962) | Merkle tree hashing, STHs, inclusion & consistency proofs, the monitor role, "detectability not prevention" trust model | CT logs X.509 certs; AXR logs execution receipts. Same math, different leaf. |
| **Sigstore — Rekor** | An append-only public transparency log as an anchor backend | AXR uses Rekor as *one* anchor option, not the system of record; the receipts themselves are AXR-native. |
| **Sigstore — Fulcio / cosign / keyless** | OIDC-based ephemeral signing identity (§8.3, Mode 2) | Optional interop; AXR's default is a long-lived Ed25519 key. |
| **in-toto / SLSA** | Per-step signed attestations forming a verifiable chain of a process | in-toto attests software *supply-chain* steps; AXR attests *runtime decision* steps of a live workflow. Conceptually the closest neighbour. |
| **C2PA** | A chained manifest of provenance assertions over an artifact | C2PA is about media provenance; AXR is about decision provenance. Similar chaining, different domain. |
| **RFC 3161 TSA** | Trusted timestamp tokens | Used as an anchor backend for signed time. |
| **OpenTimestamps** | Bitcoin-anchored, operator-independent timestamps | Used as the long-term, jurisdiction-independent anchor. No token, no trusted third party beyond Bitcoin itself. |
| **W3C PROV** | A vocabulary for provenance graphs | AXR's evidence graph (§3.4) is a concrete, signed, narrow instance of the general idea. |

The honest one-liner: **AXR 0.3 is "in-toto-style per-step attestations for live
agent workflows, made tamper-*detectable* by Certificate-Transparency-style
anchoring."** If a reader already knows those two systems, they know 90% of AXR
in one sentence — and that is a strength, not a weakness. Novelty here is in the
*target* (agent decisions, generative steps, an n8n-shaped integration) and in
the *discipline of the threat model*, not in inventing new cryptography.

### 12.1 Why not "just use" one of these directly?

A fair question, answered plainly:

- **in-toto** is built around software artifacts and build steps; bending it to
  per-execution runtime decisions with generative-step capture and an n8n Code
  node integration is more work than a purpose-built receipt schema, though a
  future AXR could emit in-toto-compatible attestations.
- **Rekor alone** gives you a log, but not the per-step receipt semantics, the
  generative-step capture, the chain-length-as-testimony model (§2.3 of 0.2),
  or the decision graph. AXR uses Rekor as plumbing, not as the product.
- **C2PA** is media-shaped. The decision domain has different fields and
  different verifiers.

AXR's bet is that agent decisions deserve the *same* rigor these systems brought
to certificates, builds, and media — and that the fastest credible path is to
reuse their primitives rather than reinvent them.

---

## 13. Status and provenance

AXR 0.2 is in production on the ECO Clean HU geo-cluster booking workflow
(`eco-clean-geo-cluster-booking-hu`, v5.0); see the 0.2 spec §9 for the live
receipt log (mixed 0.1/0.2 receipts verifying as one chain).

AXR 0.3 is a **draft specification** with a staged implementation plan:

- **Stage A (schema + verifier). IMPLEMENTED.** The 0.3 receipt schema, `step.kind`,
  `inputs` evidence graph, and the version-aware verifier checks 8–11 ship in
  `axr-core.js` / `axr-verify.js`. The Merkle / inclusion-proof / consistency-proof
  code is dependency-free and covered by test vectors (`axr-test-0.3.js`):
  inclusion proofs for every index (n=1..17) and consistency proofs for every
  (m,n) pair (n=1..16), plus tamper-fails.
- **Stage B (anchoring sidecar). IMPLEMENTED.** The out-of-band sidecar
  (`axr-anchor.js`) batches receipts into the Merkle tree, emits signed,
  chained STHs, writes back `anchor_ref`, and submits to backends. The `local`
  backend is deterministic/offline; the `opentimestamps` backend submits the
  root digest to public Bitcoin calendars and degrades to `pending_offline`
  without network. End-to-end tested (`axr-anchor-test.js`): idempotency,
  incremental anchoring, and a holding consistency proof across two STHs.
- **Stage C (generative step). IMPLEMENTED (reference).** The marker-driven 0.3
  generator (`generateReceiptsV3`) produces a generative step receipt from a node
  carrying a `__axr_gen` marker (model, params, prompt/tool/completion, usage,
  reproducibility), sets `io.decision: null`, and links the downstream
  deterministic decision via the `inputs` evidence graph. End-to-end tested
  (`axr-generative-test.js`): generator → anchoring sidecar → verifier → monitor,
  plus tamper-fails on completion-hash and a broken evidence graph. What remains
  for production is wiring a live LLM node and its `__axr_gen` marker into the
  pilot workflow; the protocol path is proven against a realistic intent-
  classifier + Brain example.
- **Stage D (monitor). IMPLEMENTED (reference).** A minimal independent monitor
  (`axr-monitor.js`) keeps a retained journal of witnessed STHs and detects
  equivocation, truncation, non-append-only rewrites, root mismatches, and bad
  signatures; a `compare` command proves split-view between two monitors. Tested
  (`axr-monitor-test.js`). For the guarantees to be *actual* in production, the
  monitor must be run by a party other than the operator — the reference
  implementation makes that deployment cheap, but does not by itself create the
  independent party.

The cryptographic and protocol layers (A, B, C, D) are implemented and tested
offline; what remains for full production assurance is wiring a live LLM node's
`__axr_gen` marker into the pilot workflow and, crucially, (D-deployment) an
*independent* operator of the monitor. Until an independent monitor actually
runs, AXR 0.3's G5/G6 guarantees are realisable but not yet realised — stated
honestly rather than implied to be finished.

---

## 14. Changelog

### 0.4 (prototype) — 2026-06-08

- **Added.** Redactable receipts: field-level salted Merkle commitments so a
  sensitive field's cleartext can be erased (GDPR Art. 17) without breaking the
  signature, the chain, or an already-anchored inclusion proof. `redactable_root`
  is signed; the cleartext detail is excluded from signature/chain/leaf hashing.
  Verifier check 13. §15.2.
- **Added.** Side-effect attestation (N1 mitigation): a signed `side_effects[]`
  array binding a claim to an external system's record (recheckable), with
  optional provider co-signature (attested). Verifier check 14. §15.1.
- **Hardened.** Canonicalization to RFC 8785 (JCS) determinism with explicit
  guards (throws on NaN/Infinity/undefined/bigint/non-plain objects instead of
  silent corruption); cross-implementation byte vectors pinned.
- **Added.** Adversarial test matrix: a valid anchored log mutated 15 ways, all
  rejected by the verifier (systematic proof of the tamper-evident claim).
- **Added.** Independent Python verifier (`axr_verify.py`, zero dependencies:
  own canonicalizer, pure-Python Ed25519 per RFC 8032, RFC 6962 Merkle) and a
  cross-implementation test proving byte-identical canonicalization and verifier
  agreement (valid and tampered) between JS and Python — the CT-style "multiple
  independent implementations agree" proof.
- **Added.** §15 Future directions: multi/side-effect/receiver attestation (A3),
  selective disclosure beyond redaction (B), monitor economics with the
  public-anchor nuance (C); and a `COMPLIANCE.md` control mapping.

### 0.3 — 2026-06-06

- **Corrected.** Tagline and trust framing: from the misleading "HTTPS … signs
  its own traffic" to the accurate Certificate Transparency model
  ("detectability, not prevention"). §0.
- **Added.** Explicit threat model: adversaries A1–A3, guarantees G1–G7,
  non-guarantees N1–N5, trust assumptions. §2.
- **Added.** Independent anchoring: RFC 6962 Merkle tree, Signed Tree Heads,
  inclusion/consistency proofs, Rekor / RFC 3161 / OpenTimestamps backends, and
  the Monitor role. §6–§7.
- **Added.** Generative-step receipts: model/param/prompt/tool/completion
  capture, evidentiary-capture-vs-reproducibility rule, decision binding,
  retention modes. §5.
- **Added.** Optional federated identity: key-bound attestations and
  Sigstore-keyless interop. §8.
- **Added.** `step.kind`, `inputs` (evidence graph), `anchor_ref` (signature-
  excluded post-hoc annotation), `actor.identity_ref`. §4.
- **Added.** Verifier checks 8–12; dependency-free inclusion-proof reference
  code. §10.
- **Added.** Prior-art alignment with CT, Sigstore, in-toto/SLSA, C2PA, RFC
  3161, OpenTimestamps, W3C PROV. §12.

### 0.2 — 2026-05-15

- Per-step input precision via `__axr_input`; `axr_version` field and
  version-aware verifier; chain-length model corrected to the pilot's real
  structure; three production bugs documented.

### 0.1 — 2026-05-14

- Initial pilot: step + workflow receipts, two-level chaining, Ed25519, SHA-256,
  canonical serialization, n8n Code-node integration.

---

## 15. Future directions (0.4+)

0.3 closed the *self-signed log* gap with independent anchoring. Honest external
review then surfaced three weaknesses that anchoring does **not** close. This
section records them and the intended direction for each, so the boundary of the
current design is explicit and the roadmap is on the record rather than implied.

### 15.1 The operator still signs (A3 / N1)

The receipt is signed by the same party that runs the workflow. Anchoring proves
*time and order*, not *truth at signing* (N1). The direction is **not** "let the
provider sign on our behalf," but **multi-attestation** — corroborating a claim
with signers the operator does not control, in increasing order of cost:

- **Side-effect attestation (cheapest, highest leverage). IMPLEMENTED (reference).** The external
  service the agent actually used emits its own evidence, which the receipt
  *references* via a signed `side_effects[]` array: the calendar API's event id,
  the payment processor's reference, the email provider's send log — plus a hash
  of the provider's response so an auditor can independently re-fetch and compare
  (recheckable). When the provider co-signs the entry with its own key
  (`attestSideEffect`), the event is cryptographically bound to a party other than
  the operator (attested). `side_effects` is part of the signed receipt; verifier
  check 14; tested in `axr-sideeffect-test.js`. The key→provider identity bootstrap
  (§8) is the remaining gap. This needs no new trust party for the recheckable
  level — it reuses attestations that already exist — and directly narrows N1.
- **Receiver attestation.** For decisions with an online counterparty, the
  receiver counter-signs "I received decision X." Strong for that subset; not
  universal (many decisions have no online receiver; the receiver may collude or
  be absent).
- **Runtime attestation (TEE).** A trusted execution environment attests that
  the receipt was produced by the expected code, moving the trust root off the
  operator. Heaviest; a later option, schema-compatible but unspecified here.

The honest framing: AXR cannot make truth-at-signing free, but it can raise the
cost of an undetectable lie by requiring **more independent signers on the events
that matter**.

### 15.2 Prompt retention and GDPR — redactable receipts (implemented), then selective disclosure

EU enterprise prompts routinely contain personal data, which collides with the
append-only design and the **GDPR right to erasure (Art. 17)**.

- **Implemented in the 0.4 prototype: field-level redactable receipts.** Sensitive
  fields are committed through a per-field **salted** Merkle tree whose root
  (`redactable_root`) is signed; the cleartext detail is excluded from the
  signature, the chain hash, and the leaf hash. A field's cleartext can therefore
  be **erased** later (drop value + salt, keep the leaf hash) while the signature,
  the chain, and the already-anchored inclusion proof all remain valid. The salt
  makes a redacted field's hash non-brute-forceable. (`buildRedactable`,
  `redactField`, `verifyRedactable`; verifier check 13; `axr-redactable-test.js`.)
- **Next layer: selective disclosure and ZK.** SD-JWT / BBS+-style signatures
  would allow revealing only a subset of claims while preserving integrity and
  unlinkability; zero-knowledge proofs would allow proving a property of the
  prompt ("contained no PII per classifier X", "followed policy Y") without
  revealing it. These are heavier and intentionally beyond the 0.4 prototype, but
  the redactable-field model is the foundation they build on.

### 15.3 Monitor economics

Certificate Transparency works because many well-resourced monitors watch a
*public commons* of certificates. AXR's logs are per-tenant and largely private,
so the naïve reading is "who will run monitors?" Two corrections narrow the
problem:

- **Public anchoring reduces the monitor count needed.** Because STH roots are
  committed to a public, append-only ledger (OpenTimestamps/Bitcoin), the
  *timestamp and append-only* properties (G4/G5) lean on the ledger itself as the
  always-on witness. Monitors are mainly needed for **equivocation** (G6), and
  even that is bounded when STH heads are publicly anchored.
- **Incentive-aligned operators exist.** The **customer** (`on_behalf_of`) has the
  strongest incentive and is the default monitor ("bring your own monitor"). An
  **insurer** underwriting agent errors can require monitoring as a policy
  condition — a clean commercial wedge. **Auditors/regulators** verify
  episodically at audit time and need not run continuous monitors thanks to the
  public anchor.

The open part is a lightweight **gossip** mechanism: each monitor publishes the
STH head it witnessed to a small shared registry, so equivocation across private
views becomes catchable without a CT-scale monitor population. This is the likely
0.4+ research item for this axis.

### 15.4 Positioning (non-normative)

AXR is **infrastructure, not a product**: an SDK + a managed transparency service
+ a compliance view, with the protocol open (the Sigstore model). Its defensible
claim is not novel cryptography but being *early and credible* in a space the EU
AI Act (Art. 12 record-keeping/traceability for high-risk systems) is making
near-mandatory. See `COMPLIANCE.md` for the control mapping (a technical-control
mapping, not legal advice). The standing platform risk — a model vendor shipping a
similar standard — is mitigated by aligning with in-toto/Sigstore now (§12) so AXR
maps onto such a standard rather than competing with it.

---

*The protocol, the generator, and the verifier were designed and built
collaboratively under the CENTAUR model. AXR 0.3 deliberately reuses the
cryptographic primitives of Certificate Transparency and Sigstore rather than
inventing new ones; its contribution is their assembly for agent accountability,
and the discipline of saying exactly what that assembly does and does not
prove.*
