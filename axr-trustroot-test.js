// ═══════════════════════════════════════════════════════════════════════════════
// AXR 0.4 - Trust root (a side-effect attestation kulcs->provider kotese) end-to-end
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-trustroot-test.js
//
// Ez bizonyitja az N1 lyuk lezarasat: trust-root NELKUL barmely kulccsal alairt
// attestation "attested"; trust-rootTAL csak a providerhez TENYLEGESEN rendelt
// kulcs az - az operator nem nevezheti sajat kulcsat 'google-calendar'-nak.
//
// Mit ellenoriz:
//   1. core.verifyTrustRoot: a root-kulccsal alairt allowlist verifikal
//   2. NEGATIV: a trust-root utolagos bovitese (uj kulcs) -> az alairas bukik
//   3. core.verifySideEffect trust-roottal: a benne levo kulcs -> attested
//   4. NEGATIV: idegen (self-attested) kulcs trust-roottal -> NEM attested + problema
//   5. end-to-end verifier --trust-root: legit kulcs -> 0
//   6. end-to-end verifier --trust-root: operator-onattesztacio -> 1
//
// Nulla kulso fuggoseg.  Kilepesi kod: 0 ha minden zold, 1 ha barmi megbukik.
// ═══════════════════════════════════════════════════════════════════════════════

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const core = require('./axr-core');

let passed = 0;
function check(name, fn) {
  try { fn(); passed++; console.log(`  ok  - ${name}`); }
  catch (e) { console.log(`  HIBA - ${name}\n        ${e.message}`); process.exitCode = 1; }
}

function kp() {
  const k = crypto.generateKeyPairSync('ed25519');
  return { priv: k.privateKey.export({ type: 'pkcs8', format: 'pem' }),
           pub: k.publicKey.export({ type: 'spki', format: 'pem' }) };
}

// szereplok: operator (receipt-alairo), egy fuggetlen root (trust-root alairo),
// a valodi stripe provider-kulcs, es egy operator-kontrollalta "alkulcs"
const op = kp();
const root = kp();
const stripe = kp();
const fake = kp(); // ezt nevezne az operator 'stripe'-nak

// trust-root: a root-kulcs alairja, hogy a 'stripe' provider kulcsa = stripe.pub
const trustRoot = core.buildTrustRoot(
  [{ provider: 'stripe', public_keys: [stripe.pub] }],
  root.priv, root.pub
);

check('core.verifyTrustRoot: root-kulccsal alairt allowlist verifikal', () => {
  const r = core.verifyTrustRoot(trustRoot);
  assert.ok(r.ok, 'a trust-root nem verifikal: ' + JSON.stringify(r.problems));
});

check('NEGATIV: trust-root utolagos bovitese -> alairas bukik', () => {
  const tampered = JSON.parse(JSON.stringify(trustRoot));
  tampered.providers[0].public_keys.push(fake.pub); // az operator becsempeszi a sajat kulcsat
  const r = core.verifyTrustRoot(tampered);
  assert.ok(!r.ok, 'a bovitett trust-root atment, pedig nem kellett volna');
});

check('core.verifySideEffect trust-roottal: valodi stripe-kulcs -> attested', () => {
  const entry = core.attestSideEffect(
    { type: 'payment.authorized', provider: 'stripe', reference: 'pi_1',
      evidence_hash: core.sha256({ id: 'pi_1' }) },
    stripe.priv, stripe.pub
  );
  const r = core.verifySideEffect(entry, trustRoot);
  assert.ok(r.ok && r.attested, 'a valodi providerkulcs nem attested: ' + JSON.stringify(r.problems));
});

check('NEGATIV: self-attested (idegen) kulcs trust-roottal -> NEM attested + problema', () => {
  // az operator a SAJAT kulcsaval ir ala, es 'stripe'-nak nevezi
  const entry = core.attestSideEffect(
    { type: 'payment.authorized', provider: 'stripe', reference: 'pi_2',
      evidence_hash: core.sha256({ id: 'pi_2' }) },
    fake.priv, fake.pub
  );
  // trust-root NELKUL: strukturalisan/alairasilag ervenyes -> attested (a regi viselkedes)
  const without = core.verifySideEffect(entry);
  assert.ok(without.attested, 'trust-root nelkul attested-nek kell lennie (visszafele komp.)');
  // trust-roottal: a kulcs nincs a stripe allowlistben -> lefokozva, problema
  const withTr = core.verifySideEffect(entry, trustRoot);
  assert.ok(!withTr.attested, 'a self-attested kulcs trust-roottal NEM lehet attested');
  assert.ok(!withTr.ok && /NINCS a trust-rootban/.test(withTr.problems.join(' ')),
    'nem a trust-root kotest jelezte: ' + JSON.stringify(withTr.problems));
});

// ── end-to-end verifier --trust-root ───────────────────────────────────────────
const sign = (o) => { const r = { ...o }; delete r.signature; r.signature = core.signReceipt(r, op.priv); return r; };

function buildLogWith(attestKp) {
  const wfId = core.uuid();
  const entry = core.attestSideEffect(
    { type: 'payment.authorized', provider: 'stripe', reference: 'pi_e2e',
      evidence_hash: core.sha256({ id: 'pi_e2e', amount: 5000 }) },
    attestKp.priv, attestKp.pub
  );
  const step = sign({
    axr_version: '0.4', receipt_type: 'step', receipt_id: core.uuid(),
    workflow_receipt_id: wfId, sequence: 1, timestamp: '2026-06-08T08:00:00.000Z',
    step: { node_name: 'Charge Card', node_type: 'n8n-nodes-base.stripe',
            kind: 'deterministic', deterministic: true, model: null },
    io: { input_hash: core.sha256('in'), output_hash: core.sha256('out'), input_summary: {},
          decision: { status: 'CHARGED' } },
    inputs: [], approval: null, previous_receipt_hash: null, anchor_ref: null,
    side_effects: [entry]
  });
  const wf = sign({
    axr_version: '0.4', receipt_type: 'workflow', receipt_id: wfId,
    workflow: { workflow_id: 'wf', workflow_version: '1', webhook_path: 'p', trigger_timestamp: 't', completion_timestamp: 't' },
    actor: { agent_id: 'a', agent_type: 'n8n-workflow', operator: 'op', on_behalf_of: 'c', identity_ref: null },
    request: { input_hash: core.sha256('raw'), customer_ref: core.customerRef('a', 'b', 'c') },
    outcome: { final_status: 'CHARGED', decision_summary: 'ok' },
    step_chain: [step.receipt_id], chain_root_hash: core.chainHash(step),
    approval: null, previous_receipt_hash: null, anchor_ref: null
  });
  return [step, wf];
}

function runVerify(dir, receipts, withTrustRoot) {
  fs.writeFileSync(path.join(dir, 'public-key.pem'), op.pub);
  fs.writeFileSync(path.join(dir, 'trust-root.json'), JSON.stringify(trustRoot));
  fs.writeFileSync(path.join(dir, 'receipts.jsonl'), receipts.map(r => JSON.stringify(r)).join('\n') + '\n');
  const args = [path.join(__dirname, 'axr-verify.js'), path.join(dir, 'receipts.jsonl'), path.join(dir, 'public-key.pem')];
  if (withTrustRoot) args.push('--trust-root', path.join(dir, 'trust-root.json'));
  try { return { code: 0, out: execFileSync('node', args, { encoding: 'utf8' }) }; }
  catch (e) { return { code: e.status == null ? -1 : e.status, out: (e.stdout || '').toString() }; }
}

check('end-to-end: valodi stripe-attestation + --trust-root -> verifier 0', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-tr-ok-'));
  const res = runVerify(dir, buildLogWith(stripe), true);
  assert.strictEqual(res.code, 0, `a valodi attestation nem ment at:\n${res.out}`);
  assert.ok(/Trust-root: ervenyes/.test(res.out), 'az osszegzes nem jelzi a trust-rootot');
  fs.rmSync(dir, { recursive: true, force: true });
});

check('end-to-end: operator-onattesztacio + --trust-root -> verifier 1', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-tr-bad-'));
  const res = runVerify(dir, buildLogWith(fake), true);
  assert.strictEqual(res.code, 1, `a self-attested kulcsot trust-roottal nem utasitotta el:\n${res.out}`);
  fs.rmSync(dir, { recursive: true, force: true });
});

console.log('-'.repeat(72));
if (process.exitCode === 1) {
  console.log(`EREDMENY: NEM minden teszt zold (${passed} sikeres). Lasd a [HIBA] sorokat.`);
} else {
  console.log(`EREDMENY: mind a ${passed} teszt zold. A trust-root (N1 kulcs->provider kotes) mukodik.`);
}
