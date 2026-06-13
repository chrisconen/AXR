# AXR dev-log — a verifiable snapshot of AXR's own development journal

**AXR records and verifies the integrity of its own development journal.**

This directory is a byte-frozen AXR log generated from `agents/journal.jsonl` —
the shared journal of the three-AI workbench (Fable / Meridian / NEXUS) that
built AXR 0.5–1.0. Each journal entry (who did what, why, when, which files)
is a signed **journal-entry receipt**; the whole log is anchored into an RFC
6962 Signed Tree Head, and that STH is **witness-cosigned** by the two reviewer
agents (Meridian, NEXUS). It verifies under the full 1.0 stack:

```bash
# from the repo root
node   axr-verify.js devlog/receipts.jsonl devlog/op.pubkey.pem devlog/sth.jsonl devlog/anchors.jsonl \
  --trust-root devlog/trust-root.json --control devlog/control.jsonl --require-witnesses
python axr_verify.py devlog/receipts.jsonl devlog/op.pubkey.pem devlog/sth.jsonl devlog/anchors.jsonl \
  --trust-root devlog/trust-root.json --control devlog/control.jsonl --require-witnesses
```

Regenerate it live against the current journal: `npm run dogfood`.

## What this proves — and what it does NOT

- **Proves:** the journal has not been altered since signing, the entries are
  in a fixed order under one anchored tree, and an STH is accepted only with a
  threshold of independent witness cosignatures. Concretely: if an AI wrote a
  mistake, this proves it *really wrote that, then* — and that nobody
  cosmetically edited it out afterwards.
- **Does NOT prove** that any journal entry was *true* when written (N1 — truth
  at signing is out of scope; AXR is an integrity layer, not an oracle).
- **Independence — what is real here:** the two witness cosignatures in
  `sth.jsonl` were produced by the *actual* reviewer agents, each in its **own
  separate process** with a key it **generated and held itself**:
  - **Meridian** (Codex / GPT-5.5) generated `meridian.pubkey.pem`
    (`sha256:08d5e6dc…`) and cosigned via `axr-witness.js sign` in its own
    process.
  - **NEXUS** (Gemini) generated `nexus.pubkey.pem` (`sha256:c73214af…`) and
    cosigned the same way.

  The orchestrator (Fable) **never saw either private key** — it only assembled
  the two finished cosignatures onto the STH. So this is genuine *process-level*
  independence, not a single-process simulation.
- **Remaining caveat (honest):** custody is still **same-machine** — the agents
  ran on one host, not in separate security zones. Cross-zone custody
  (e.g. Fable@Anthropic, NEXUS@Google, Meridian on isolated infra) is the
  production deployment, and is what makes the zero-trust property fully real.
  The mechanism and the per-process key custody shown here are genuine; the
  cross-zone separation is the only thing the deployment still adds.

The framing is deliberate: AXR is **a tool in the human auditor's hand to
hold autonomous AI systems accountable** — not a system that governs itself.

*No private keys are committed here — only public keys and the signed/anchored
artifact, exactly like any externally verifiable AXR log.*
