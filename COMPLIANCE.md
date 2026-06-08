# AXR as a Compliance Control

**Status:** informational, non-normative.
**This is not legal advice.** It maps AXR's *technical* mechanisms to the kinds of
record-keeping, traceability, and data-protection expectations that commonly apply
to automated decision systems. Whether any specific regulation applies to a given
deployment — and whether AXR satisfies it — is a question for qualified counsel and
the relevant authority, not for this document. Article references are provided as
orientation and must be confirmed against the current consolidated legal text.

AXR is **infrastructure, not a compliance product**. It produces tamper-evident,
independently anchorable evidence of what an automated workflow did. It does not,
by itself, make a system compliant; it provides a technical control that a
compliance programme can rely on.

---

## 1. What AXR provides as a control

| Capability | Mechanism | Where |
|---|---|---|
| Automatic, per-execution event records | Signed step + workflow receipts | §3–§4 |
| Integrity / tamper-evidence of those records | Ed25519 signatures + two-level hash chaining | §6 |
| Independent, timely anchoring (not self-asserted time) | RFC 6962 Merkle tree → Signed Tree Heads → OpenTimestamps / Rekor / RFC 3161 | §6–§7 |
| Detection of deletion, reordering, backdating, equivocation | Inclusion + consistency proofs, an independent **Monitor** | §7.5, §10 |
| Capture of AI (LLM) invocations as evidence | Generative-step receipts (model, params, prompt/tool/completion hashes) | §5 |
| Traceability of a decision to the model output it consumed | `inputs` evidence graph | §3.4, §5.5 |
| Data-subject erasure without breaking the audit trail | Field-level salted redactable commitments | §15.2 |
| Minimised personal data in the record by default | `customer_ref` is a hash of PII, not the PII | §4.3 |

---

## 2. EU AI Act (Regulation (EU) 2024/1689) — orientation mapping

For systems classified **high-risk**, the Act sets expectations around automatic
logging, traceability over the lifecycle, and post-market monitoring. AXR is a
natural technical control for the *record-keeping* obligations specifically.

| Regulatory expectation (functional description) | How AXR supports it | Honest caveat |
|---|---|---|
| **Record-keeping / automatic logging** of events over the system's lifetime (commonly **Art. 12**) | Every decision-relevant step produces a signed, chained, append-only receipt; logs are independently anchored so they cannot be silently altered after the fact | AXR records *what the workflow asserts it did*. It does not validate the decision's correctness (see spec §2.4 N1). |
| **Traceability** of how an output was produced | The `inputs` evidence graph links a deterministic decision to the generative output it consumed; generative receipts pin model id, params, prompt/completion hashes | Generative steps are captured as *evidence*, not as *reproducible* computations (§5.4). |
| **Logs kept by the deployer** of a high-risk system (deployer obligations) | The receipt log + anchors are exportable, independently verifiable artifacts a deployer can retain and hand to an auditor | Retention duration/format obligations are deployment-specific; AXR provides the artifact, not the policy. |
| **Post-market monitoring / incident evidence** | Anchored, tamper-evident receipts give a defensible timeline; the Monitor detects after-the-fact tampering | Requires an actually-running, ideally independent, monitor (N4). |
| **Transparency to the deployer/affected person** | `decision_summary` + structured `decision` provide a human-readable, machine-checkable account of each outcome | Communicating to end-users is an application concern AXR feeds, not replaces. |

> The Act's specific article numbers, thresholds, and which obligations fall on
> *provider* vs *deployer* must be confirmed with counsel for each deployment.
> AXR's contribution is the **evidence layer**, which is necessary but not
> sufficient for compliance.

---

## 3. GDPR (Regulation (EU) 2016/679) — orientation mapping

The hard tension is **append-only integrity vs. the right to erasure**. AXR is
designed to hold both.

| GDPR principle (functional description) | How AXR supports it | Caveat |
|---|---|---|
| **Right to erasure** (commonly **Art. 17**) | Field-level **redactable receipts** (spec §15.2): a sensitive field's cleartext can be deleted (drop value + salt, keep the leaf hash) while the signature, chain, and anchored inclusion proof all remain valid | The *commitment* (a salted hash) remains; the salt makes it non-brute-forceable, but whether a salted hash counts as erased for a given case is a legal determination |
| **Integrity and confidentiality** (commonly **Art. 5(1)(f)**) | Signatures + hash chaining + anchoring provide strong integrity; retention modes (`none`/`encrypted`/`plain`) and redaction support confidentiality | Key management is operator-grade by default (spec §11.7) |
| **Data minimisation** (commonly **Art. 5(1)(c)**) | `customer_ref` stores a hash of name+email+phone rather than the values; default retention is hash-only | The deployer chooses what to put in `input_summary` and retained content |
| **Storage limitation** (commonly **Art. 5(1)(e)**) | Redaction enables removing personal cleartext when its purpose expires, without discarding the integrity record | Retention schedules are a deployer policy |

---

## 4. What AXR explicitly does **not** establish

To prevent over-reliance (and over-selling), the non-guarantees from the spec
threat model are restated here as compliance limits:

- **Not proof of truth at signing (N1).** AXR proves a record was not altered,
  suppressed, or backdated after the fact — not that it was honest when made.
  Use side-effect/receiver attestation (spec §15.1) to corroborate.
- **Not protection against a stolen key (N2).** A compromised key signs valid
  receipts; anchoring bounds the damage in time but does not prevent it.
- **Not effective without a monitor (N4).** The anti-tampering guarantees become
  *actual* only when an independent party runs the Monitor.
- **Not legal compliance.** AXR is a control. Compliance is a programme:
  policies, DPIAs, retention schedules, human oversight, and the rest — none of
  which AXR provides.

---

## 5. Practical deployment checklist (technical, non-exhaustive)

- [ ] Anchor STH roots to at least one operator-independent backend (OpenTimestamps recommended).
- [ ] Run a Monitor as a party other than the workflow operator (customer, auditor, or insurer).
- [ ] Use `encrypted` or redactable retention for any prompt/completion that may carry personal data.
- [ ] Keep `customer_ref` as a hash; never put raw PII in `input_summary`.
- [ ] Define and document a retention + redaction schedule; redact on erasure requests.
- [ ] Rotate and protect the signing key; publish key rotations as anchored identity attestations (spec §8).
- [ ] Retain `receipts.jsonl`, `sth.jsonl`, and `anchors.jsonl` together — they verify as one set.

---

*See `AXR-SPEC-0.3.md` §2 (threat model), §7 (anchoring), §10 (verification), and
§15 (future directions) for the technical detail behind every row above.*
