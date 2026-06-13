// ═══════════════════════════════════════════════════════════════════════════════
// AXR 1.0 - embedded_succession governance cleanup (EMBEDDED_BYPASS) teszt
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-embedded-bypass-test.js   (Python esetek kihagyva, ha nincs)
//
// Mit ellenoriz:
//   1. Sidecar guard: --succession + --control egyutt -> a sidecar DOB (1.0
//      governance cleanup, self-lockout-megelozes)
//   2. Standalone --succession (control NELKUL) -> tovabbra is mukodik (0.5 mod,
//      olvasas/verify marad)
//   3. EMBEDDED_BYPASS: egy STH embedded_succession-t hordoz, control log
//      hasznalatban van, de a rekord NINCS a control logban -> a monitor es
//      mindket verifier fail-closed (a withholding-csatorna megkerulese)
//   4. Nincs bypass: ha ugyanaz a rekord a control logban IS szerepel ->
//      elfogadott (dedup)
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
const T0 = () => '2026-06-13T14:00:00.000Z';
const LOG = 'axr:embbypass:v1';
const root = genKey(), A = genKey(), B = genKey(), Rc1 = genKey();

const trustRoot = s.buildTrustRoot({ providers: [],
  logs: [{ log_id: LOG, genesis: { sth: A.publicKey, receipt: Rc1.publicKey } }] },
  root.privateKey, root.publicKey, T0);
const sthSucc = s.buildKeySuccession({ log_id: LOG, role: 'sth',
  predecessor_fingerprint: s.keyFingerprint(A.publicKey), successor_public_key: B.publicKey,
  effective_from_tree_size: 4 }, root.privateKey, T0);

let prevWf = null;
function sign(obj, priv) { const r = { ...obj }; delete r.signature; r.signature = axr.signReceipt(r, priv); return r; }
function appendRun(p, priv, tag) {
  const wfId = axr.uuid(); const steps = []; let prev = null;
  for (let i = 0; i < 2; i++) {
    const st = sign({ axr_version: '0.3', receipt_type: 'step', receipt_id: axr.uuid(),
      workflow_receipt_id: wfId, sequence: i + 1, timestamp: T0(),
      step: { node_name: `N${i}`, node_type: 'n8n-nodes-base.code', kind: 'deterministic', deterministic: true, model: null },
      io: { input_hash: axr.sha256(`${tag}-in-${i}`), output_hash: axr.sha256(`${tag}-out-${i}`), input_summary: {}, decision: null },
      inputs: [], approval: null, previous_receipt_hash: prev, anchor_ref: null }, priv);
    steps.push(st); prev = axr.chainHash(st);
  }
  const wf = sign({ axr_version: '0.3', receipt_type: 'workflow', receipt_id: wfId,
    workflow: { workflow_id: 'wf', workflow_version: '1', webhook_path: 'p', trigger_timestamp: T0(), completion_timestamp: T0() },
    actor: { agent_id: 'a', agent_type: 'n8n-workflow', operator: 'op', on_behalf_of: 'c', identity_ref: null },
    request: { input_hash: axr.sha256(`${tag}-raw`), customer_ref: axr.customerRef('a', 'b', 'c') },
    outcome: { final_status: tag, available: false, decision_summary: tag },
    step_chain: steps.map(x => x.receipt_id), chain_root_hash: axr.chainHash(steps[steps.length - 1]),
    approval: null, previous_receipt_hash: prevWf, anchor_ref: null }, priv);
  prevWf = axr.chainHash(wf);
  fs.appendFileSync(p, [...steps, wf].map(r => JSON.stringify(r)).join('\n') + '\n');
}

(async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-emb-'));
  const mkdir = (n) => { const d = path.join(tmp, n); fs.mkdirSync(d); return d; };

  // ─────────────────────────────────────────────────────────────────────────
  section('1. Sidecar guard: --succession + --control egyutt -> dob');
  const d1 = mkdir('guard');
  const rp1 = path.join(d1, 'receipts.jsonl'); fs.writeFileSync(rp1, '');
  const tr1 = path.join(d1, 'tr.json'); fs.writeFileSync(tr1, JSON.stringify(trustRoot) + '\n');
  const ctl1 = path.join(d1, 'control.jsonl'); fs.writeFileSync(ctl1, JSON.stringify(sthSucc) + '\n');
  prevWf = null; appendRun(rp1, Rc1.privateKey, 'G1');
  const base1 = { receiptsPath: rp1, sthPath: path.join(d1, 'sth.jsonl'), anchorsPath: path.join(d1, 'anchors.jsonl'),
    backends: ['local'], logId: LOG, now: T0 };
  await runAnchor({ ...base1, privateKeyPem: A.privateKey });
  prevWf = prevWf; appendRun(rp1, B.privateKey, 'G2');
  let threw = false;
  try { await runAnchor({ ...base1, privateKeyPem: B.privateKey, succession: sthSucc,
    controlPath: ctl1, controlTrustRootPath: tr1 }); }
  catch (e) { threw = /governance cleanup|control log mellett/.test(e.message); }
  ok(threw, 'a sidecar DOB --succession + --control egyutt (1.0)');

  // ─────────────────────────────────────────────────────────────────────────
  section('2. Standalone --succession (control nelkul) -> mukodik');
  const d2 = mkdir('standalone');
  const rp2 = path.join(d2, 'receipts.jsonl'); fs.writeFileSync(rp2, '');
  const base2 = { receiptsPath: rp2, sthPath: path.join(d2, 'sth.jsonl'), anchorsPath: path.join(d2, 'anchors.jsonl'),
    backends: ['local'], logId: LOG, now: T0 };
  prevWf = null; appendRun(rp2, Rc1.privateKey, 'S1');
  await runAnchor({ ...base2, privateKeyPem: A.privateKey });
  appendRun(rp2, B.privateKey, 'S2');
  await runAnchor({ ...base2, privateKeyPem: B.privateKey, succession: sthSucc });
  const sth2 = fs.readFileSync(base2.sthPath, 'utf8').trim().split('\n').map(JSON.parse).find(x => x.embedded_succession);
  ok(sth2 && JSON.stringify(sth2.embedded_succession) === JSON.stringify(sthSucc),
    'standalone --succession beagyazza (0.5 mod, control nelkul)');

  // ─────────────────────────────────────────────────────────────────────────
  section('3. EMBEDDED_BYPASS: embedded-only succession control log mellett');
  // a 2. szekcio logja (embedded successionnel) - most control loggal ELLENORIZVE,
  // de a control log NEM tartalmazza az embedded rekordot -> bypass
  const trPath2 = path.join(d2, 'tr.json'); fs.writeFileSync(trPath2, JSON.stringify(trustRoot) + '\n');
  const emptyCtl = path.join(d2, 'control.jsonl'); fs.writeFileSync(emptyCtl, JSON.stringify(
    s.buildWitnessSet({ log_id: LOG, witness_threshold: 1, effective_from_tree_size: 1,
      witnesses: [{ public_key: genKey().publicKey }] }, root.privateKey, T0)) + '\n'); // van control log, de nincs benne sthSucc
  const keyPath2 = path.join(d2, 'rc1.pem'); fs.writeFileSync(keyPath2, Rc1.publicKey);
  const ctlRecs = fs.readFileSync(emptyCtl, 'utf8').trim().split('\n').map(JSON.parse);
  const resByp = pollMonitor({ sthPath: base2.sthPath, publicKeyPem: A.publicKey,
    statePath: path.join(d2, 'mon.json'), receiptsPath: rp2, trustRoot: [trustRoot], control: ctlRecs, now: T0 });
  ok(codes(resByp).includes('EMBEDDED_BYPASS'),
    'monitor: control log mellett az embedded-only succession -> EMBEDDED_BYPASS sertes');
  function jverify(extra) {
    const args = [path.join(__dirname, 'axr-verify.js'), rp2, keyPath2, base2.sthPath, base2.anchorsPath, ...extra];
    try { execFileSync('node', args, { stdio: 'pipe' }); return 0; } catch (e) { return e.status == null ? -1 : e.status; }
  }
  function pyverify(extra) {
    const args = [path.join(__dirname, 'axr_verify.py'), rp2, keyPath2, base2.sthPath, base2.anchorsPath, ...extra];
    try { execFileSync(PYTHON, args, { stdio: 'pipe' }); return 0; } catch (e) { return e.status == null ? -1 : e.status; }
  }
  ok(jverify(['--trust-root', trPath2, '--control', emptyCtl]) === 1, 'JS verifier: EMBEDDED_BYPASS -> exit 1');
  if (PYTHON) ok(pyverify(['--trust-root', trPath2, '--control', emptyCtl]) === 1, 'Python verifier: ugyanez -> exit 1');

  // ─────────────────────────────────────────────────────────────────────────
  section('4. Nincs bypass: a rekord a control logban IS szerepel');
  const fullCtl = path.join(d2, 'control-full.jsonl');
  fs.writeFileSync(fullCtl, [sthSucc, ctlRecs[0]].map(r => JSON.stringify(r)).join('\n') + '\n');
  const resOk = pollMonitor({ sthPath: base2.sthPath, publicKeyPem: A.publicKey,
    statePath: path.join(d2, 'mon2.json'), receiptsPath: rp2, trustRoot: [trustRoot],
    control: [sthSucc, ctlRecs[0]], now: T0 });
  ok(!codes(resOk).includes('EMBEDDED_BYPASS'),
    'a control logban szereplo (dedup) embedded succession NEM bypass');

  console.log(`\nOsszesen: ${pass} ok, ${fail} hiba` + (PYTHON ? '' : ' (Python esetek kihagyva)'));
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('VARATLAN HIBA:', e); process.exit(1); });
