# Contributing to AXR

Thanks for considering a contribution. AXR is small, dependency-free, and its
credibility rests on its tests, so the bar for changes is "the proof still holds."

## Principles

- **Zero runtime dependencies.** The core, verifiers, anchor, and monitor use only
  the Node and Python standard libraries. Do not add runtime dependencies; if a
  change seems to need one, open an issue to discuss first.
- **The 0.2 wire format is frozen.** Receipts written by 0.1/0.2/0.3 must keep
  verifying byte-for-byte. New work is additive (new fields, new optional checks,
  new flags) and must not change existing signatures, leaf hashes, or chain hashes.
- **Two implementations must agree.** Any change to canonicalization or Merkle
  logic must keep the JS (`axr-core.js`) and Python (`axr_verify.py`) verifiers
  byte-identical. The cross-implementation test is the contract.
- **No emojis** anywhere — code, comments, docs, UI, commit messages.

## Development

```bash
git clone https://github.com/chrisconen/AXR.git
cd AXR
node --version     # >= 18
python3 --version  # >= 3.10
npm test           # runs every axr-*-test.js, including JS<->Python parity
```

There is no build step and nothing to install.

## Tests

- Every test file matching `axr-*-test.js` is auto-discovered by `run-tests.js`,
  so a new test is included in CI automatically — there is no list to maintain.
- A change to behavior needs a test. A bug fix should add a test that fails before
  the fix and passes after.
- Security-relevant changes should extend `axr-adversarial-test.js` (the tamper
  matrix) and/or `axr-crossverify-test.js` (cross-implementation agreement).
- `npm test` must be green before opening a pull request. CI runs the full suite
  across Node 18/20/22 and Python 3.10/3.11/3.12.

## Commits and pull requests

- Use clear, imperative commit subjects (e.g. "fix: reject STH with wrong key").
- Describe what security property or behavior a change affects, and how it was
  tested. The pull request template prompts for this.
- Keep changes focused; unrelated refactors belong in separate PRs.

## Reporting security issues

Do not file public issues for vulnerabilities. See [SECURITY.md](SECURITY.md).
