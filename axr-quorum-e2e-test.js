// ═══════════════════════════════════════════════════════════════════════════════
// AXR 0.6 - kvorum-root end-to-end (sidecar -> monitor -> JS + Python verifier)
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-quorum-e2e-test.js   (Python esetek kihagyva, ha nincs)
//
// Mit ellenoriz:
//   1. 2-of-3 kvorum-root + kvorum-alairt rotaciok a TERMELESI uton: a monitor
//      elfogadja (KEY_ROTATED_AUTHORIZED), JS es Python verifier exit 0
//   2. Red-team: kvorum alatti (1 alairasos) succession -> monitor sertes,
//      mindket verifier elutasit
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

const T0 = () => '2026-06-12T12:00:00.000Z';
const LOG = 'axr:quorum-e2e:v1';

// kvorum: R1..R3; operator sth: A -> B; operator receipt: Rc1 -> Rc2
const R1 = genKey(), R2 = genKey(), R3 = genKey();
const A = genKey(), B = genKey(), Rc1 = genKey(), Rc2 = genKey();

const trustRoot = s.buildQuorumTrustRoot({
  providers: [], root_keys: [R1.publicKey, R2.publicKey, R3.publicKey], threshold: 2,
  logs: [{ log_id: LOG, genesis: { sth: A.publicKey, receipt: Rc1.publicKey } }]
}, [R1.privateKey, R2.privateKey], T0);

function quorumSucc(role, predPub, succKey, signers) {
  return s.buildQuorumKeySuccession({
    log_id: LOG, role, predecessor_fingerprint: s.keyFingerprint(predPub),
    successor_public_key: succKey.publicKey, effective_from_tree_size: 4, reason: 'scheduled'
  }, signers, T0);
}
const sthSucc = quorumSucc('sth', A.publicKey, B, [R2.privateKey, R3.privateKey]);
const recSucc = quorumSucc('receipt', Rc1.publicKey, Rc2, [R1.privateKey, R3.privateKey]);

// teljes workflow-futas alairt receiptekkel (mint a verify-succession tesztben)
function sign(obj, privPem) {
  const r = { ...obj }; delete r.signature;
  r.signature = axr.signReceipt(r, privPem);
  return r;
}
function makeRun(privPem, prevWorkflowHash, tag) {
  const wfId = axr.uuid();
  const steps = [];
  let prev = null;
  for (let i = 0; i < 2; i++) {
    const st = sign({
      axr_version: '0.3', receipt_type: 'step', receipt_id: axr.uuid(),
      workflow_receipt_id: wfId, sequence: i + 1, timestamp: T0(),
      step: { node_name: `Node ${i}`, node_type: 'n8n-nodes-base.code', kind: 'deterministic',
              deterministic: true, model: null },
      io: { input_hash: axr.sha256(`${tag}-in-${i}`), output_hash: axr.sha256(`${tag}-out-${i}`),
            input_summary: { idx: i }, decision: null },
      inputs: [], approval: null, previous_receipt_hash: prev, anchor_ref: null
    }, privPem);
    steps.push(st);
    prev = axr.chainHash(st);
  }
  const wf = sign({
    axr_version: '0.3', receipt_type: 'workflow', receipt_id: wfId,
    workflow: { workflow_id: 'wf', workflow_version: '1', webhook_path: 'p',
                trigger_timestamp: T0(), completion_timestamp: T0() },
    actor: { agent_id: 'agent', agent_type: 'n8n-workflow', operator: 'op', on_behalf_of: 'cust', identity_ref: null },
    request: { input_hash: axr.sha256(`${tag}-raw`), customer_ref: axr.customerRef('a', 'b', 'c') },
    outcome: { final_status: tag, available: false, decision_summary: tag },
    step_chain: steps.map(x => x.receipt_id),
    chain_root_hash: axr.chainHash(steps[steps.length - 1]),
    approval: null, previous_receipt_hash: prevWorkflowHash || null, anchor_ref: null
  }, privPem);
  return { receipts: [...steps, wf], workflowHash: axr.chainHash(wf) };
}

async function buildLog(dir, sthSuccession) {
  const receiptsPath = path.join(dir, 'receipts.jsonl');
  const base = { receiptsPath, sthPath: path.join(dir, 'sth.jsonl'),
    anchorsPath: path.join(dir, 'anchors.jsonl'), backends: ['local'], logId: LOG, now: T0 };
  const run1 = makeRun(Rc1.privateKey, null, 'RUN1');
  fs.writeFileSync(receiptsPath, run1.receipts.map(r => JSON.stringify(r)).join('\n') + '\n');
  await runAnchor({ ...base, privateKeyPem: A.privateKey });
  const run2 = makeRun(Rc2.privateKey, run1.workflowHash, 'RUN2');
  fs.appendFileSync(receiptsPath, run2.receipts.map(r => JSON.stringify(r)).join('\n') + '\n');
  await runAnchor({ ...base, privateKeyPem: B.privateKey, succession: sthSuccession });
  return base;
}

function runVerifier(cmdName, dir, aux) {
  const isPy = cmdName !== 'node';
  const script = isPy ? 'axr_verify.py' : 'axr-verify.js';
  const args = [path.join(__dirname, script),
    path.join(dir, 'receipts.jsonl'), aux.keyPath,
    path.join(dir, 'sth.jsonl'), path.join(dir, 'anchors.jsonl'),
    '--trust-root', aux.trPath, '--successions', aux.succPath];
  try { execFileSync(cmdName, args, { stdio: 'pipe' }); return 0; }
  catch (e) { return e.status == null ? -1 : e.status; }
}

(async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-qe2e-'));
  const mkdir = (n) => { const d = path.join(tmp, n); fs.mkdirSync(d); return d; };
  function writeAux(dir, succs) {
    const trPath = path.join(dir, 'trust-root.json');
    fs.writeFileSync(trPath, JSON.stringify(trustRoot) + '\n');
    const succPath = path.join(dir, 'successions.jsonl');
    fs.writeFileSync(succPath, succs.map(x => JSON.stringify(x)).join('\n') + '\n');
    const keyPath = path.join(dir, 'rec-genesis.pem');
    fs.writeFileSync(keyPath, Rc1.publicKey);
    return { trPath, succPath, keyPath };
  }

  // ─────────────────────────────────────────────────────────────────────────
  section('1. Kvorum-root happy path a termelesi uton');
  const dirGood = mkdir('good');
  const good = await buildLog(dirGood, sthSucc);
  const auxGood = writeAux(dirGood, [recSucc]);
  const res1 = pollMonitor({ sthPath: good.sthPath, publicKeyPem: A.publicKey,
    statePath: path.join(dirGood, 'mon.json'), receiptsPath: good.receiptsPath,
    trustRoot, now: T0 });
  ok(res1.ok, 'monitor: nincs sertes (kvorum-autorizalt rotacio): ' + JSON.stringify(res1.violations));
  ok(res1.notices.join(' | ').includes('KEY_ROTATED_AUTHORIZED'), 'monitor: KEY_ROTATED_AUTHORIZED');
  ok(runVerifier('node', dirGood, auxGood) === 0, 'JS verifier: exit 0');
  if (PYTHON) ok(runVerifier(PYTHON, dirGood, auxGood) === 0, 'Python verifier: exit 0 (cross-impl)');
  else console.log('  SKIP - nincs python');

  // ─────────────────────────────────────────────────────────────────────────
  section('2. Red-team: kvorum alatti succession');
  const underSth = s.buildQuorumKeySuccession({
    log_id: LOG, role: 'sth', predecessor_fingerprint: s.keyFingerprint(A.publicKey),
    successor_public_key: B.publicKey, effective_from_tree_size: 4, reason: 'under-quorum'
  }, [R1.privateKey], T0); // csak 1 alairas a 2 helyett
  const underRec = s.buildQuorumKeySuccession({
    log_id: LOG, role: 'receipt', predecessor_fingerprint: s.keyFingerprint(Rc1.publicKey),
    successor_public_key: Rc2.publicKey, effective_from_tree_size: 4, reason: 'under-quorum'
  }, [R1.privateKey], T0);
  const dirBad = mkdir('bad');
  const bad = await buildLog(dirBad, underSth);
  const auxBad = writeAux(dirBad, [underRec]);
  const res2 = pollMonitor({ sthPath: bad.sthPath, publicKeyPem: A.publicKey,
    statePath: path.join(dirBad, 'mon.json'), receiptsPath: bad.receiptsPath,
    trustRoot, now: T0 });
  ok(!res2.ok && res2.violations.some(v => v.code === 'KEY_CHANGED_UNAUTHORIZED'),
    'monitor: kvorum alatti beagyazott succession -> KEY_CHANGED_UNAUTHORIZED');
  ok(runVerifier('node', dirBad, auxBad) === 1, 'JS verifier: exit 1');
  if (PYTHON) ok(runVerifier(PYTHON, dirBad, auxBad) === 1, 'Python verifier: exit 1 (cross-impl egyetertes)');

  console.log(`\nOsszesen: ${pass} ok, ${fail} hiba` + (PYTHON ? '' : ' (Python esetek kihagyva)'));
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('VARATLAN HIBA:', e); process.exit(1); });
