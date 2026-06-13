// ═══════════════════════════════════════════════════════════════════════════════
// AXR 0.8 - witness end-to-end (sidecar -> witnessek -> monitor + JS/Python verifier)
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-witness-e2e-test.js   (Python esetek kihagyva, ha nincs)
//
// Mit ellenoriz a TERMELESI uton (a witness_set a control logban, alairt futasok):
//   1. Threshold teljesul: az STH-k threshold-nyi cosignature-rel -> a monitor
//      es mindket verifier elfogadja (--require-witnesses mellett is)
//   2. UNDER_WITNESSED: cosignature nelkul -> default notice (verifier exit 0),
//      --require-witnesses mellett violation (monitor + mindket verifier exit 1)
//   3. WITNESS_COSIGNATURE_INVALID: nem-deklaralt witness cosignature-je ->
//      mindig sertes (monitor + mindket verifier), --require-witnesses nelkul is
//
// Nulla kulso fuggoseg.  Kilepesi kod: 0 zold, 1 hiba.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const axr = require('./axr-core');
const s = require('./axr-succession');
const { runAnchor } = require('./axr-anchor');
const { pollMonitor } = require('./axr-monitor');

let pass = 0, fail = 0;
function ok(cond, name) { if (cond) { pass++; } else { fail++; console.log('  FAIL: ' + name); } }
function section(t) { console.log('\n' + t); }
function codes(r) { return r.violations.map(v => v.code); }

function genKey() {
  const kp = crypto.generateKeyPairSync('ed25519');
  return { privateKey: kp.privateKey.export({ type: 'pkcs8', format: 'pem' }),
           publicKey: kp.publicKey.export({ type: 'spki', format: 'pem' }) };
}
function findPython() {
  for (const cand of ['python3', 'python']) {
    try { const v = execFileSync(cand, ['--version'], { encoding: 'utf8', stdio: 'pipe' });
      if (/^Python 3\./.test(v.trim())) return cand; } catch (e) {}
  }
  return null;
}
const PYTHON = findPython();

const T0 = () => '2026-06-13T12:00:00.000Z';
const LOG = 'axr:witness-e2e:v1';
const root = genKey(), op = genKey(), W1 = genKey(), W2 = genKey(), Wx = genKey();

const trustRoot = s.buildTrustRoot({ providers: [],
  logs: [{ log_id: LOG, genesis: { sth: op.publicKey, receipt: op.publicKey } }] },
  root.privateKey, root.publicKey, T0);
const witnessSet = s.buildWitnessSet({ log_id: LOG, witness_threshold: 2, effective_from_tree_size: 1,
  witnesses: [{ name: 'auditor', public_key: W1.publicKey }, { name: 'customer', public_key: W2.publicKey }] },
  root.privateKey, T0);

// alairt workflow-futasok (op = receipt-genesis), hogy a verifier receipt-
// alairas-ellenorzese is atmenjen (a bare leaf elbukna a 0.8 receipt-idovonalon)
let prevWf = null;
function sign(obj) { const r = { ...obj }; delete r.signature; r.signature = axr.signReceipt(r, op.privateKey); return r; }
function appendRun(p, tag) {
  const wfId = axr.uuid(); const steps = []; let prev = null;
  for (let i = 0; i < 2; i++) {
    const st = sign({ axr_version: '0.3', receipt_type: 'step', receipt_id: axr.uuid(),
      workflow_receipt_id: wfId, sequence: i + 1, timestamp: T0(),
      step: { node_name: `N${i}`, node_type: 'n8n-nodes-base.code', kind: 'deterministic', deterministic: true, model: null },
      io: { input_hash: axr.sha256(`${tag}-in-${i}`), output_hash: axr.sha256(`${tag}-out-${i}`), input_summary: {}, decision: null },
      inputs: [], approval: null, previous_receipt_hash: prev, anchor_ref: null });
    steps.push(st); prev = axr.chainHash(st);
  }
  const wf = sign({ axr_version: '0.3', receipt_type: 'workflow', receipt_id: wfId,
    workflow: { workflow_id: 'wf', workflow_version: '1', webhook_path: 'p', trigger_timestamp: T0(), completion_timestamp: T0() },
    actor: { agent_id: 'a', agent_type: 'n8n-workflow', operator: 'op', on_behalf_of: 'c', identity_ref: null },
    request: { input_hash: axr.sha256(`${tag}-raw`), customer_ref: axr.customerRef('a', 'b', 'c') },
    outcome: { final_status: tag, available: false, decision_summary: tag },
    step_chain: steps.map(x => x.receipt_id), chain_root_hash: axr.chainHash(steps[steps.length - 1]),
    approval: null, previous_receipt_hash: prevWf, anchor_ref: null });
  prevWf = axr.chainHash(wf);
  fs.appendFileSync(p, [...steps, wf].map(r => JSON.stringify(r)).join('\n') + '\n');
}
function readSths(p) { return fs.readFileSync(p, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse); }

// Egy onallo, alairt log felepitese egy sajat konyvtarban (control-commitmenttel).
async function buildLog(dir, cosignWith) {
  prevWf = null;
  const receiptsPath = path.join(dir, 'receipts.jsonl');
  const sthPath = path.join(dir, 'sth.jsonl');
  const trPath = path.join(dir, 'trust-root.json');
  const controlPath = path.join(dir, 'control.jsonl');
  const keyPath = path.join(dir, 'op.pem');
  fs.writeFileSync(trPath, JSON.stringify(trustRoot) + '\n');
  fs.writeFileSync(controlPath, JSON.stringify(witnessSet) + '\n');
  fs.writeFileSync(keyPath, op.publicKey);
  fs.writeFileSync(receiptsPath, '');
  const base = { receiptsPath, sthPath, anchorsPath: path.join(dir, 'anchors.jsonl'),
    backends: ['local'], logId: LOG, now: T0, controlPath, controlTrustRootPath: trPath };
  appendRun(receiptsPath, 'RUN1');
  await runAnchor({ ...base, privateKeyPem: op.privateKey });
  appendRun(receiptsPath, 'RUN2');
  await runAnchor({ ...base, privateKeyPem: op.privateKey });
  if (cosignWith) {
    const out = readSths(sthPath).map(sth => sth.record_type === 'sth'
      ? s.assembleWitnessCosignatures(sth, cosignWith.map(pk => s.cosignWitness(sth, pk))) : sth);
    fs.writeFileSync(sthPath, out.map(r => JSON.stringify(r)).join('\n') + '\n');
  }
  return { receiptsPath, sthPath, anchorsPath: base.anchorsPath, trPath, controlPath, keyPath,
    control: () => fs.readFileSync(controlPath, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse) };
}
function runVerify(cmd, L, extra) {
  const script = cmd === 'node' ? 'axr-verify.js' : 'axr_verify.py';
  const args = [path.join(__dirname, script), L.receiptsPath, L.keyPath, L.sthPath, L.anchorsPath,
    '--trust-root', L.trPath, '--control', L.controlPath, ...(extra || [])];
  try { execFileSync(cmd, args, { stdio: 'pipe' }); return 0; }
  catch (e) { return e.status == null ? -1 : e.status; }
}

(async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-we2e-'));
  const mkdir = (n) => { const d = path.join(tmp, n); fs.mkdirSync(d); return d; };

  // ─────────────────────────────────────────────────────────────────────────
  section('1. Threshold teljesul (W1 + W2 cosignol)');
  const Lok = await buildLog(mkdir('ok'), [W1.privateKey, W2.privateKey]);
  const res1 = pollMonitor({ sthPath: Lok.sthPath, publicKeyPem: op.publicKey, statePath: path.join(tmp, 'mon1.json'),
    receiptsPath: Lok.receiptsPath, trustRoot: [trustRoot], control: Lok.control(), requireWitnesses: true, now: T0 });
  ok(res1.ok, 'monitor (--require-witnesses): nincs sertes: ' + JSON.stringify(res1.violations));
  ok(runVerify('node', Lok, ['--require-witnesses']) === 0, 'JS verifier --require-witnesses: exit 0');
  if (PYTHON) ok(runVerify(PYTHON, Lok, ['--require-witnesses']) === 0, 'Python verifier --require-witnesses: exit 0 (cross-impl)');

  // ─────────────────────────────────────────────────────────────────────────
  section('2. UNDER_WITNESSED (nincs cosignature)');
  const Lun = await buildLog(mkdir('under'), null);
  const res2def = pollMonitor({ sthPath: Lun.sthPath, publicKeyPem: op.publicKey, statePath: path.join(tmp, 'mon2.json'),
    receiptsPath: Lun.receiptsPath, trustRoot: [trustRoot], control: Lun.control(), now: T0 });
  ok(res2def.ok && /UNDER_WITNESSED/.test(res2def.notices.join(' | ')),
    'monitor default: UNDER_WITNESSED notice, NINCS sertes');
  const res2req = pollMonitor({ sthPath: Lun.sthPath, publicKeyPem: op.publicKey, statePath: path.join(tmp, 'mon2b.json'),
    receiptsPath: Lun.receiptsPath, trustRoot: [trustRoot], control: Lun.control(), requireWitnesses: true, now: T0 });
  ok(!res2req.ok && codes(res2req).includes('UNDER_WITNESSED'),
    'monitor --require-witnesses: UNDER_WITNESSED violation');
  ok(runVerify('node', Lun) === 0, 'JS verifier default: exit 0 (UNDER_WITNESSED puha jelzes)');
  ok(runVerify('node', Lun, ['--require-witnesses']) === 1, 'JS verifier --require-witnesses: exit 1');
  if (PYTHON) {
    ok(runVerify(PYTHON, Lun) === 0, 'Python verifier default: exit 0');
    ok(runVerify(PYTHON, Lun, ['--require-witnesses']) === 1, 'Python verifier --require-witnesses: exit 1 (cross-impl)');
  }

  // ─────────────────────────────────────────────────────────────────────────
  section('3. WITNESS_COSIGNATURE_INVALID (nem-deklaralt witness)');
  const Lbad = await buildLog(mkdir('bad'), [W1.privateKey, Wx.privateKey]);
  const res3 = pollMonitor({ sthPath: Lbad.sthPath, publicKeyPem: op.publicKey, statePath: path.join(tmp, 'mon3.json'),
    receiptsPath: Lbad.receiptsPath, trustRoot: [trustRoot], control: Lbad.control(), now: T0 });
  ok(!res3.ok && codes(res3).includes('WITNESS_COSIGNATURE_INVALID'),
    'monitor (default mod is): nem-deklaralt witness -> WITNESS_COSIGNATURE_INVALID sertes');
  ok(runVerify('node', Lbad) === 1, 'JS verifier (--require-witnesses NELKUL is): exit 1');
  if (PYTHON) ok(runVerify(PYTHON, Lbad) === 1, 'Python verifier: exit 1 (cross-impl)');

  // ─────────────────────────────────────────────────────────────────────────
  section('4. WITNESS_SET_AMBIGUOUS (ket utkozo witness_set azonos effective_from-ra)');
  // Meridian-review: az ambiguous policy fail-closed, NEM csendes kihagyas
  // (kulonben ki lehetne kapcsolni a witness-kaput). A control logba ket eltero
  // witness_set kerul ugyanarra a hatarra.
  const Lamb = await buildLog(mkdir('amb'), [W1.privateKey, W2.privateKey]);
  const ws2 = s.buildWitnessSet({ log_id: LOG, witness_threshold: 1, effective_from_tree_size: 1,
    witnesses: [{ name: 'other', public_key: Wx.publicKey }] }, root.privateKey, T0);
  fs.appendFileSync(Lamb.controlPath, JSON.stringify(ws2) + '\n');
  const resAmb = pollMonitor({ sthPath: Lamb.sthPath, publicKeyPem: op.publicKey, statePath: path.join(tmp, 'mon4.json'),
    receiptsPath: Lamb.receiptsPath, trustRoot: [trustRoot], control: Lamb.control(), now: T0 });
  ok(!resAmb.ok && codes(resAmb).includes('WITNESS_SET_AMBIGUOUS'),
    'monitor: ket utkozo witness_set -> WITNESS_SET_AMBIGUOUS sertes (default modban is, fail-closed)');
  ok(runVerify('node', Lamb) === 1, 'JS verifier: ambiguous witness_set -> exit 1 (--require-witnesses nelkul is)');
  if (PYTHON) ok(runVerify(PYTHON, Lamb) === 1, 'Python verifier: ambiguous -> exit 1 (cross-impl, fail-closed)');

  console.log(`\nOsszesen: ${pass} ok, ${fail} hiba` + (PYTHON ? '' : ' (Python esetek kihagyva)'));
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('VARATLAN HIBA:', e); process.exit(1); });
