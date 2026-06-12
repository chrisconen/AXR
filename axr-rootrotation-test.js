// ═══════════════════════════════════════════════════════════════════════════════
// AXR 0.6 - root-rotacio / recovery (trust-root lanc) teszt
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-rootrotation-test.js   (Python esetek kihagyva, ha nincs)
//
// Mit ellenoriz:
//   1. Kvorum genesis -> kvorum utod (recovery-ut): lanc verifikal, az
//      effektiv root a lanc vege
//   2. Migracio: 0.5-os egykulcsos genesis -> kvorum utod
//   3. Red-team: kvorum alatti utod; onmagat autorizalo utod (uj kulcsokkal
//      alairva); tort elod-hash; hamisitott utod-body; nem-genesis lanc-fej
//   4. End-to-end: monitor + JS/Python verifier lanc-fajllal; a monitor
//      genesis-pinje a lanc-csere kiserletet TRUST_ROOT_CHANGED-kent fogja el
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

function genKey() {
  const kp = crypto.generateKeyPairSync('ed25519');
  return {
    privateKey: kp.privateKey.export({ type: 'pkcs8', format: 'pem' }),
    privateKeyObj: kp.privateKey,
    publicKey: kp.publicKey.export({ type: 'spki', format: 'pem' })
  };
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

const T0 = () => '2026-06-12T13:00:00.000Z';
const LOG = 'axr:rootrot-test:v1';

// regi kvorum: R1..R3 (2-of-3); uj kvorum: S1..S3 (2-of-3); operator: A, Rc1
const R1 = genKey(), R2 = genKey(), R3 = genKey();
const S1 = genKey(), S2 = genKey(), S3 = genKey();
const A = genKey(), Rc1 = genKey(), X = genKey();
const LOGS = [{ log_id: LOG, genesis: { sth: A.publicKey, receipt: Rc1.publicKey } }];

// ───────────────────────────────────────────────────────────────────────────
section('1. Kvorum genesis -> kvorum utod (recovery)');
const genesis = s.buildQuorumTrustRoot({ providers: [], logs: LOGS,
  root_keys: [R1.publicKey, R2.publicKey, R3.publicKey], threshold: 2 },
  [R1.privateKey, R2.privateKey], T0);
const succRoot = s.buildTrustRootSuccessor({ providers: [], logs: LOGS,
  root_keys: [S1.publicKey, S2.publicKey, S3.publicKey], threshold: 2 },
  genesis, [R1.privateKey, R3.privateKey], T0);
const chain = [genesis, succRoot];
const cv1 = s.verifyTrustRootChain(chain);
ok(cv1.ok, 'a ket-elemu lanc verifikal: ' + cv1.problems.join('; '));
ok(cv1.effective === succRoot, 'az effektiv root a lanc vege (az uj kulcskeszlet kormanyoz)');
ok(!s.verifyTrustRoot(succRoot).ok, 'az utod-root onmagaban NEM ervenyes (csak lancban, a pinned fejtol)');
// az uj kvorum mar tovabbi rekordokat autorizalhat (a recovery lenyege)
const succAfterRotation = s.buildQuorumKeySuccession({
  log_id: LOG, role: 'sth', predecessor_fingerprint: s.keyFingerprint(A.publicKey),
  successor_public_key: X.publicKey, effective_from_tree_size: 100, reason: 'post-recovery'
}, [S1.privateKey, S2.privateKey], T0);
ok(s.verifyKeySuccession(succAfterRotation, cv1.effective).ok,
  'a rotacio utan az UJ kvorum autorizal successiont');
ok(!s.verifyKeySuccession(succAfterRotation, genesis).ok,
  'a regi root onmagaban mar nem fogadja el az uj kvorum alairasait');

// ───────────────────────────────────────────────────────────────────────────
section('2. Migracio: 0.5 egykulcsos genesis -> kvorum utod');
const oldSingle = genKey();
const genSingle = s.buildTrustRoot({ providers: [], logs: LOGS }, oldSingle.privateKey, oldSingle.publicKey, T0);
const succFromSingle = s.buildTrustRootSuccessor({ providers: [], logs: LOGS,
  root_keys: [S1.publicKey, S2.publicKey, S3.publicKey], threshold: 2 },
  genSingle, [oldSingle.privateKey], T0);
const cv2 = s.verifyTrustRootChain([genSingle, succFromSingle]);
ok(cv2.ok && cv2.effective === succFromSingle, '0.5 egykulcsos root kvorum-utodra rotal (migracios ut)');

// ───────────────────────────────────────────────────────────────────────────
section('3. Red-team');
// 3a. kvorum alatti utod (1 alairas a 2 helyett)
const under = s.buildTrustRootSuccessor({ providers: [], logs: LOGS,
  root_keys: [S1.publicKey], threshold: 1 }, genesis, [R1.privateKey], T0);
ok(!s.verifyTrustRootChain([genesis, under]).ok, 'kvorum alatti utod -> a lanc ervenytelen');
// 3b. onmagat autorizalo utod: az UJ kulcsok irjak ala (nem az elod kvoruma)
const selfAuth = s.buildTrustRootSuccessor({ providers: [], logs: LOGS,
  root_keys: [S1.publicKey, S2.publicKey, S3.publicKey], threshold: 2 },
  genesis, [S1.privateKey, S2.privateKey], T0);
ok(!s.verifyTrustRootChain([genesis, selfAuth]).ok, 'onmagat autorizalo utod -> elutasitva');
// 3c. tort elod-hash
const brokenLink = JSON.parse(JSON.stringify(succRoot));
brokenLink.predecessor_trust_root_hash = axr.sha256('masik');
ok(!s.verifyTrustRootChain([genesis, brokenLink]).ok, 'tort predecessor-hash -> elutasitva');
// 3d. hamisitott utod-body (no re-sign)
const tampered = JSON.parse(JSON.stringify(succRoot));
tampered.threshold = 1;
ok(!s.verifyTrustRootChain([genesis, tampered]).ok, 'utolag hamisitott utod-body -> elutasitva');
// 3e. nem-genesis lanc-fej (predecessor-hash-t hordoz)
ok(!s.verifyTrustRootChain([succRoot]).ok, 'utod-rekord lanc-fejkent -> elutasitva (nincs onmagat pinnelo root)');

// ───────────────────────────────────────────────────────────────────────────
section('4. End-to-end: lanc-fajl a monitorban es a verifierekben');
(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-rotr-'));
  // egyszeru log: A irja ala az STH-kat, Rc1 a receipteket (nincs operator-rotacio)
  const receiptsPath = path.join(dir, 'receipts.jsonl');
  const base = { receiptsPath, sthPath: path.join(dir, 'sth.jsonl'),
    anchorsPath: path.join(dir, 'anchors.jsonl'), backends: ['local'], logId: LOG, now: T0 };
  function signR(obj) { const r = { ...obj }; r.signature = axr.signReceipt(r, Rc1.privateKey); return r; }
  const wfId = axr.uuid();
  const step = signR({ axr_version: '0.3', receipt_type: 'step', receipt_id: axr.uuid(),
    workflow_receipt_id: wfId, sequence: 1, timestamp: T0(),
    step: { node_name: 'N', node_type: 'n8n-nodes-base.code', kind: 'deterministic', deterministic: true, model: null },
    io: { input_hash: axr.sha256('in'), output_hash: axr.sha256('out'), input_summary: {}, decision: null },
    inputs: [], approval: null, previous_receipt_hash: null, anchor_ref: null });
  const wf = signR({ axr_version: '0.3', receipt_type: 'workflow', receipt_id: wfId,
    workflow: { workflow_id: 'wf', workflow_version: '1', webhook_path: 'p',
                trigger_timestamp: T0(), completion_timestamp: T0() },
    actor: { agent_id: 'a', agent_type: 'n8n-workflow', operator: 'op', on_behalf_of: 'c', identity_ref: null },
    request: { input_hash: axr.sha256('raw'), customer_ref: axr.customerRef('a', 'b', 'c') },
    outcome: { final_status: 'OK', available: false, decision_summary: 'OK' },
    step_chain: [step.receipt_id], chain_root_hash: axr.chainHash(step),
    approval: null, previous_receipt_hash: null, anchor_ref: null });
  fs.writeFileSync(receiptsPath, [step, wf].map(r => JSON.stringify(r)).join('\n') + '\n');
  await runAnchor({ ...base, privateKeyPem: A.privateKey });

  const chainPath = path.join(dir, 'trust-chain.jsonl');
  fs.writeFileSync(chainPath, chain.map(r => JSON.stringify(r)).join('\n') + '\n');
  const keyPath = path.join(dir, 'rc1.pem');
  fs.writeFileSync(keyPath, Rc1.publicKey);

  const stPath = path.join(dir, 'mon.json');
  const res1 = pollMonitor({ sthPath: base.sthPath, publicKeyPem: A.publicKey, statePath: stPath,
    receiptsPath, trustRootPath: chainPath, now: T0 });
  ok(res1.ok, 'monitor: lanc-fajllal konzisztens: ' + JSON.stringify(res1.violations));
  ok(JSON.parse(fs.readFileSync(stPath, 'utf8')).trust_root_genesis_hash === axr.sha256(genesis),
    'a journal a lanc-fej (genesis) hash-et pinneli');

  // lanc-csere kiserlet: a tamado SAJAT, onmagaban konzisztens lanca
  const evil = s.buildQuorumTrustRoot({ providers: [], logs: LOGS,
    root_keys: [X.publicKey], threshold: 1 }, [X.privateKey], T0);
  const evilPath = path.join(dir, 'evil-chain.jsonl');
  fs.writeFileSync(evilPath, JSON.stringify(evil) + '\n');
  const res2 = pollMonitor({ sthPath: base.sthPath, publicKeyPem: A.publicKey, statePath: stPath,
    receiptsPath, trustRootPath: evilPath, now: T0 });
  ok(!res2.ok && res2.violations.some(v => v.code === 'TRUST_ROOT_CHANGED'),
    'lanc-csere (mas genesis) -> TRUST_ROOT_CHANGED, fail-closed');

  // verifierek a lanc-fajllal
  function runVerifier(cmdName) {
    const script = cmdName === 'node' ? 'axr-verify.js' : 'axr_verify.py';
    const args = [path.join(__dirname, script), receiptsPath, keyPath,
      base.sthPath, base.anchorsPath, '--trust-root', chainPath];
    try { execFileSync(cmdName, args, { stdio: 'pipe' }); return 0; }
    catch (e) { return e.status == null ? -1 : e.status; }
  }
  ok(runVerifier('node') === 0, 'JS verifier lanc-fajllal: exit 0');
  if (PYTHON) ok(runVerifier(PYTHON) === 0, 'Python verifier lanc-fajllal: exit 0 (cross-impl)');
  else console.log('  SKIP - nincs python');

  console.log(`\nOsszesen: ${pass} ok, ${fail} hiba` + (PYTHON ? '' : ' (Python esetek kihagyva)'));
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('VARATLAN HIBA:', e); process.exit(1); });
