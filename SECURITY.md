# Security Policy

AXR is a cryptographic accountability protocol. Its value depends entirely on the
soundness of its tamper-evidence guarantees, so security reports are taken
seriously and handled with priority.

## Supported versions

AXR ships several maturity layers in one repository (see the "Maturity by layer"
table in the README). Security fixes target the layers below:

| Layer | Version | Supported |
|-------|---------|-----------|
| Core (signing, chaining, canonicalization, Merkle) | 0.2 | Yes |
| Anchoring, monitor | 0.3 | Yes |
| Redactable, side-effect, trust-root | 0.4 | Yes (evolving) |

The `main` branch is the integration line; the most recent `v0.x.y` tag is the
reference point for a report.

## Reporting a vulnerability

Please do **not** open a public issue for a security vulnerability.

Use GitHub's private vulnerability reporting: on the repository, go to the
**Security** tab and choose **Report a vulnerability**. This opens a private
advisory visible only to the maintainers.

When reporting, please include where practical:

- the affected file(s) and version/commit,
- a description of the weakness and the security property it breaks
  (e.g. tamper-evidence, signature soundness, anchor integrity, canonicalization
  determinism, cross-implementation divergence),
- a minimal reproduction — ideally a failing test or a crafted receipt/log that
  the verifier wrongly accepts or rejects,
- the impact you foresee.

## What qualifies

Because the central claim is "tamper-evident and independently verifiable," the
following are in scope and especially valuable:

- a mutation of a signed log that the verifier (JS or Python) accepts,
- a divergence between the JS and Python verifiers on the same input,
- a canonicalization input that produces different bytes across implementations,
- an inclusion/consistency/MMR proof that validates against the wrong tree,
- a side-effect attestation that passes `--trust-root` without its key being in
  the allowlist,
- key-separation bypass (an STH accepted under `--sth-key` that was not signed by
  that key).

## Out of scope (documented limitations)

These are known and documented in the README "Known limitations"; reports about
them are welcome as feature discussions rather than vulnerabilities:

- operator-level private-key exfiltration (no HSM/threshold key management),
- self-declared `agent_id` (no central registry),
- uniform per-run timestamp,
- final Bitcoin proof-of-work verification, which is delegated to the `ots` CLI.

## Response

We aim to acknowledge a report within a few days, agree on a disclosure timeline,
and credit reporters who wish to be credited once a fix ships.
