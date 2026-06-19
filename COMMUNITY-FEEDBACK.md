# Community feedback — the roadmap, free, from the target audience

This file tracks unsolicited, substantive feedback from practitioners who started
*extending* AXR (not praising it). Two channels, two days, four people — the
project's own go-to-market win condition: *strangers open issues/questions because
they want to use it.* Credit is given by name, because contributions that count
build community.

How to use this file: log each substantive input with its source, the gap it
points at, and the status. Convert the worthwhile ones into spec/code work, with
the source credited in the README/CHANGELOG when it ships.

---

## 2026-06 — first wave (n8n community forum + X)

### 1. Storage before pruning — **shipped (docs)**

- **Source:** nguyenthieutoan (n8n community forum, "Top Supporter").
- **Gap:** n8n prunes execution data by default (`EXECUTIONS_DATA_PRUNE` +
  `EXECUTIONS_DATA_MAX_AGE`). Anyone relying on execution history or a Data Table
  to hold receipts keeps the cryptographic chain but loses the execution context
  that ties each receipt to its run.
- **Reality check (verified in code):** the pilot is unaffected — `axr-n8n-node.js`
  writes append-only JSONL to a bind-mounted volume
  (`/home/node/.n8n/axr/receipts-hu.jsonl`), *outside* n8n's execution data. So
  this was a missing warning, not a code defect.
- **Outcome:** README n8n "Storage" section gained an explicit
  durable-external-storage-before-pruning paragraph, crediting the forum thread.

### 2. Behavioral legibility as a first-class property — **shipped (positioning)**

- **Source:** X commenter ("...the interesting failure mode is not only tampering
  after the fact, it is mismatched intent vs executed branch, which your booking
  bug caught").
- **Insight:** AXR delivers two distinct things that had been conflated —
  *tamper-evidence* (the cryptographic floor) and *behavioral legibility* (the
  daily value: the receipt makes the workflow's actual behavior readable enough
  that an internal contradiction surfaces, even with no tampering and valid
  signatures). Bug B was exactly that.
- **Outcome:** README "What AXR does" now splits the two properties explicitly
  ("Tamper-evidence is the cryptographic floor. Behavioral legibility is what
  earns its keep day to day."), and Bug B / the production-findings closer name
  the property.

### 3. Error-path receipts — **planned (code, next dev cycle)**

- **Source:** nguyenthieutoan (n8n community forum).
- **Gap (verified in code):** the generator covers the happy path and explicit
  rejections (`final_status`). A hard failure — node throw, workflow error-out —
  currently degrades to a loud `__axr.error` passthrough and gets **no signed
  receipt**, even though a failed run is arguably the most important thing to have
  evidence of.
- **Proposal:** an `AXR Mark` node on the Error Trigger path so failed runs also
  get signed receipts — the audit trail covers the happy *and* error path.
- **Scope guardrails:** this extends generator *coverage*, **not** the wire format
  (frozen 1.x contract stays untouched). The error receipt must be clearly a
  failure-state receipt (distinct `step.kind` or status), not a normal decision.
  Step-gated: generator-level plan + test → n8n-node sample → guide update, with a
  confirmation gate between steps. Credit Nguyen on ship.

---

*Sources for this wave: n8n community forum (nguyenthieutoan ×2) + X commenter.
Every item was checked against the actual code. The wire format is frozen in 1.x —
none of these break it.*
