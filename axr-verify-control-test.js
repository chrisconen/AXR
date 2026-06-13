// ═══════════════════════════════════════════════════════════════════════════════
// AXR 0.7 - verifier control-log (JS + Python cross-impl)
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-verify-control-test.js   (Python esetek kihagyva, ha nincs)
//
// Mit ellenoriz (JS es Python EGYETERTES accept ES reject):
//   1. Happy path: control-commitmentes log + teljes control log -> exit 0;
//      a control logbeli receipt-succession a rotacion ativelo receipteket is
//      autorizalja (a --successions flag nelkul, csak --control-bol)
//   2. CONTROL_ROOT_MISMATCH: mas tartalmu control log -> exit 1
//   3. CONTROL_WITHHELD: rovidebb control log -> exit 1 (a verifier offline,
//      azonnal fail-closed)
//   4. Ervenytelen control-rekord (hamis root) -> exit 1
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

let pass = 0, fail = 0;
function ok(cond, name) { if (cond) { pass++; } else { fail++; console.log('  FAIL: ' + name); } }
function section(t) { console.log('\n' + t); }

function genKey() {
  const kp = crypto.generateKeyPairSync('ed25519');
  return { privateKey: kp.privateKey.export({ type: 'pkcs8', format: 'pem' }),
           publicKey: kp.publicKey.export({ type: 'spki', format: 'pem' }) };
}
function findPython() {
  for (const cand of ['python3', 'python']) {
    try {
      const v = execFileSync(cand, ['--version'], { encoding: 'utf8', stdio: 'pipe' });
      if (/^Python 3\./.test(v.trim())) return cand;
    } catch (e) { /* kovetkezo */ }
  }
  return null;
}
const PYTHON = findPython();

const T0 = () => '2026-06-12T17:00:00.000Z';
const LOG = 'axr:verify-control:v1';
const root = genKey(), sthA = genKey(), Rc1 = genKey(), Rc2 = genKey(), fakeRoot = genKey();

const trustRoot = s.buildTrustRoot({ providers: [],
  logs: [{ log_id: LOG, genesis: { sth: sthA.publicKey, receipt: Rc1.publicKey } }] },
  root.privateKey, root.publicKey, T0);
// receipt-role succession a control logban: Rc1 -> Rc2 @ 4
const recSucc = s.buildKeySuccession({ log_id: LOG, role: 'receipt',
  predecessor_fingerprint: s.keyFingerprint(Rc1.publicKey), successor_public_key: Rc2.publicKey,
  effective_from_tree_size: 4 }, root.privateKey, T0);

function sign(obj, privPem) { const r = { ...obj }; delete r.signature; r.signature = axr.signReceipt(r, privPem); return r; }
function makeRun(privPem, prevWorkflowHash, tag) {
  const wfId = axr.uuid();
  const steps = [];
  let prev = null;
  for (let i = 0; i < 2; i++) {
    const st = sign({ axr_version: '0.3', receipt_type: 'step', receipt_id: axr.uuid(),
      workflow_receipt_id: wfId, sequence: i + 1, timestamp: T0(),
      step: { node_name: `N${i}`, node_type: 'n8n-nodes-base.code', kind: 'deterministic', deterministic: true, model: null },
      io: { input_hash: axr.sha256(`${tag}-in-${i}`), output_hash: axr.sha256(`${tag}-out-${i}`), input_summary: { idx: i }, decision: null },
      inputs: [], approval: null, previous_receipt_hash: prev, anchor_ref: null }, privPem);
    steps.push(st); prev = axr.chainHash(st);
  }
  const wf = sign({ axr_version: '0.3', receipt_type: 'workflow', receipt_id: wfId,
    workflow: { workflow_id: 'wf', workflow_version: '1', webhook_path: 'p', trigger_timestamp: T0(), completion_timestamp: T0() },
    actor: { agent_id: 'a', agent_type: 'n8n-workflow', operator: 'op', on_behalf_of: 'c', identity_ref: null },
    request: { input_hash: axr.sha256(`${tag}-raw`), customer_ref: axr.customerRef('a', 'b', 'c') },
    outcome: { final_status: tag, available: false, decision_summary: tag },
    step_chain: steps.map(x => x.receipt_id), chain_root_hash: axr.chainHash(steps[steps.length - 1]),
    approval: null, previous_receipt_hash: prevWorkflowHash || null, anchor_ref: null }, privPem);
  return { receipts: [...steps, wf], workflowHash: axr.chainHash(wf) };
}

async function buildLog(dir, controlPath, trPath) {
  const receiptsPath = path.join(dir, 'receipts.jsonl');
  const base = { receiptsPath, sthPath: path.join(dir, 'sth.jsonl'),
    anchorsPath: path.join(dir, 'anchors.jsonl'), backends: ['local'], logId: LOG, now: T0 };
  // Rc1 irja 1..3, Rc2 irja 4..6 (a control-beli receipt-succession autorizalja)
  const run1 = makeRun(Rc1.privateKey, null, 'RUN1');
  fs.writeFileSync(receiptsPath, run1.receipts.map(r => JSON.stringify(r)).join('\n') + '\n');
  await runAnchor({ ...base, privateKeyPem: sthA.privateKey, controlPath, controlTrustRootPath: trPath });
  const run2 = makeRun(Rc2.privateKey, run1.workflowHash, 'RUN2');
  fs.appendFileSync(receiptsPath, run2.receipts.map(r => JSON.stringify(r)).join('\n') + '\n');
  await runAnchor({ ...base, privateKeyPem: sthA.privateKey, controlPath, controlTrustRootPath: trPath });
  return base;
}

(async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-vctl-'));
  const mkdir = (n) => { const d = path.join(tmp, n); fs.mkdirSync(d); return d; };

  function aux(dir, controlContent) {
    const trPath = path.join(dir, 'trust-root.json'); fs.writeFileSync(trPath, JSON.stringify(trustRoot) + '\n');
    const controlPath = path.join(dir, 'control.jsonl'); fs.writeFileSync(controlPath, controlContent);
    const keyPath = path.join(dir, 'rc1.pem'); fs.writeFileSync(keyPath, Rc1.publicKey);
    return { trPath, controlPath, keyPath };
  }
  function runV(cmd, dir, a, controlArg) {
    const script = cmd === 'node' ? 'axr-verify.js' : 'axr_verify.py';
    const args = [path.join(__dirname, script), path.join(dir, 'receipts.jsonl'), a.keyPath,
      path.join(dir, 'sth.jsonl'), path.join(dir, 'anchors.jsonl'),
      '--trust-root', a.trPath, '--control', controlArg || a.controlPath];
    try { execFileSync(cmd, args, { stdio: 'pipe' }); return 0; }
    catch (e) { return e.status == null ? -1 : e.status; }
  }

  // ─────────────────────────────────────────────────────────────────────────
  section('1. Happy path (a control-beli receipt-succession autorizal)');
  const dir1 = mkdir('good');
  const a1 = aux(dir1, JSON.stringify(recSucc) + '\n');
  await buildLog(dir1, a1.controlPath, a1.trPath);
  ok(runV('node', dir1, a1) === 0, 'JS: exit 0 (--control-bol jon a receipt-rotacio autorizacioja)');
  if (PYTHON) ok(runV(PYTHON, dir1, a1) === 0, 'Python: exit 0 (cross-impl)');

  // ─────────────────────────────────────────────────────────────────────────
  section('2. CONTROL_ROOT_MISMATCH');
  // a verifierhez MAS tartalmu control logot adunk: az elso (commitolt) rekordot
  // kicsereljuk (a hozzafuzes onmagaban nem torne, mert a commitment csak az
  // elso control_size rekordot koti - a csere viszont igen)
  const otherRec = s.buildKeyRevocation({ log_id: LOG, role: 'receipt',
    revoked_fingerprint: s.keyFingerprint(Rc2.publicKey), revoked_at_tree_size: 9 }, root.privateKey, T0);
  const mmPath = path.join(dir1, 'control-mm.jsonl');
  fs.writeFileSync(mmPath, JSON.stringify(otherRec) + '\n');
  ok(runV('node', dir1, a1, mmPath) === 1, 'JS: kicserelt elso rekord -> CONTROL_ROOT_MISMATCH, exit 1');
  if (PYTHON) ok(runV(PYTHON, dir1, a1, mmPath) === 1, 'Python: ugyanez -> exit 1');

  // ─────────────────────────────────────────────────────────────────────────
  section('3. CONTROL_WITHHELD (rovidebb control log)');
  const emptyPath = path.join(dir1, 'control-empty.jsonl');
  fs.writeFileSync(emptyPath, '');
  ok(runV('node', dir1, a1, emptyPath) === 1, 'JS: ures control log a commitolt 1 helyett -> exit 1');
  if (PYTHON) ok(runV(PYTHON, dir1, a1, emptyPath) === 1, 'Python: ugyanez -> exit 1');

  // ─────────────────────────────────────────────────────────────────────────
  section('4. Ervenytelen control-rekord (hamis root)');
  // uj log, aminek a sidecar-ja elfogadna? NEM - a sidecar verify-olna. Ezert
  // a verifier-oldali ellenorzest kulon teszteljuk: jo logot epitunk, de a
  // verifierhez egy hamis rekordot tartalmazo control logot adunk (a commitment
  // emiatt nem fog egyezni ES a rekord sem verifikal)
  const forged = s.buildKeySuccession({ log_id: LOG, role: 'receipt',
    predecessor_fingerprint: s.keyFingerprint(Rc1.publicKey), successor_public_key: Rc2.publicKey,
    effective_from_tree_size: 4 }, fakeRoot.privateKey, T0);
  const forgedPath = path.join(dir1, 'control-forged.jsonl');
  fs.writeFileSync(forgedPath, JSON.stringify(forged) + '\n');
  ok(runV('node', dir1, a1, forgedPath) === 1, 'JS: hamis root-tal alairt control-rekord -> exit 1');
  if (PYTHON) ok(runV(PYTHON, dir1, a1, forgedPath) === 1, 'Python: ugyanez -> exit 1');

  // ─────────────────────────────────────────────────────────────────────────
  section('5. Commitolo STH + hianyzo --control flag (NEXUS-review)');
  // ha az STH-k commitolnak, de a verifier NEM kap --control-t, az NEM csendes
  // atlepes (0.6 fallback) - hanem CONTROL_WITHHELD, fail-closed
  function runVnoCtl(cmd, dir, a) {
    const script = cmd === 'node' ? 'axr-verify.js' : 'axr_verify.py';
    const args = [path.join(__dirname, script), path.join(dir, 'receipts.jsonl'), a.keyPath,
      path.join(dir, 'sth.jsonl'), path.join(dir, 'anchors.jsonl'), '--trust-root', a.trPath];
    try { execFileSync(cmd, args, { stdio: 'pipe' }); return 0; }
    catch (e) { return e.status == null ? -1 : e.status; }
  }
  ok(runVnoCtl('node', dir1, a1) === 1, 'JS: commitolo STH + nincs --control -> exit 1 (CONTROL_WITHHELD)');
  if (PYTHON) ok(runVnoCtl(PYTHON, dir1, a1) === 1, 'Python: ugyanez -> exit 1');

  console.log(`\nOsszesen: ${pass} ok, ${fail} hiba` + (PYTHON ? '' : ' (Python esetek kihagyva)'));
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('VARATLAN HIBA:', e); process.exit(1); });
