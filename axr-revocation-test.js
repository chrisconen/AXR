// ═══════════════════════════════════════════════════════════════════════════════
// AXR 0.6 - revokacio (key_revocation, 3-szintu szabaly) teszt
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-revocation-test.js   (Python esetek kihagyva, ha nincs)
//
// Mit ellenoriz:
//   1. Rekord: build/verify (single + kvorum), hamisitas, idegen log
//   2. Idovonal: revoked_from a szegmensen; legkorabbi hatar gyoz;
//      nem-letezo kulcs revokacioja jelzett
//   3. A 3-szintu szabaly a verifierekben (JS + Python cross-impl):
//      anchorolt pre-boundary -> ervenyes; bizonyitek nelkuli pre-boundary ->
//      fail-closed; hatar utani -> KEY_REVOKED
//   4. Monitor: hatar utani STH -> KEY_REVOKED; pre-boundary STH-k ervenyesek;
//      hamis revokacio -> REVOCATION_UNAUTHORIZED
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

const T0 = () => '2026-06-12T14:00:00.000Z';
const LOG = 'axr:revoke-test:v1';

const root = genKey(), A = genKey(), B = genKey(), Rc1 = genKey(), Rc2 = genKey(), fakeRoot = genKey();
const fpRc1 = s.keyFingerprint(Rc1.publicKey);

const trustRoot = s.buildTrustRoot({
  providers: [],
  logs: [{ log_id: LOG, genesis: { sth: A.publicKey, receipt: Rc1.publicKey } }]
}, root.privateKey, root.publicKey, T0);

// ───────────────────────────────────────────────────────────────────────────
section('1. Rekord: build/verify');
const rev = s.buildKeyRevocation({
  log_id: LOG, role: 'receipt', revoked_fingerprint: fpRc1,
  revoked_at_tree_size: 4, reason: 'compromise'
}, root.privateKey, T0);
ok(s.verifyKeyRevocation(rev, root.publicKey).ok, 'single-alairt revokacio verifikal (PEM horgony)');
ok(s.verifyKeyRevocation(rev, trustRoot).ok, 'trust-root objektum horgonnyal is');
const Q1 = genKey(), Q2 = genKey(), Q3 = genKey();
const qTr = s.buildQuorumTrustRoot({ providers: [], root_keys: [Q1.publicKey, Q2.publicKey, Q3.publicKey],
  threshold: 2, logs: [{ log_id: LOG, genesis: { sth: A.publicKey, receipt: Rc1.publicKey } }] },
  [Q1.privateKey, Q2.privateKey], T0);
const revQ = s.buildQuorumKeyRevocation({ log_id: LOG, role: 'receipt', revoked_fingerprint: fpRc1,
  revoked_at_tree_size: 4 }, [Q1.privateKey, Q3.privateKey], T0);
ok(s.verifyKeyRevocation(revQ, qTr).ok, 'kvorum-alairt revokacio verifikal');
ok(!s.verifyKeyRevocation(s.buildQuorumKeyRevocation({ log_id: LOG, role: 'receipt',
  revoked_fingerprint: fpRc1, revoked_at_tree_size: 4 }, [Q1.privateKey], T0), qTr).ok,
  'kvorum alatti revokacio -> elutasitva');
const tampered = { ...rev, revoked_at_tree_size: 100 };
ok(!s.verifyKeyRevocation(tampered, root.publicKey).ok, 'hamisitott revokacio -> elutasitva');
const forged = s.buildKeyRevocation({ log_id: LOG, role: 'receipt', revoked_fingerprint: fpRc1,
  revoked_at_tree_size: 4 }, fakeRoot.privateKey, T0);
ok(!s.verifyKeyRevocation(forged, root.publicKey).ok, 'hamis root-tal alairt -> elutasitva');

// ───────────────────────────────────────────────────────────────────────────
section('2. Idovonal: revoked_from');
const tl = s.buildKeyTimeline(Rc1.publicKey, [], 'receipt', root.publicKey, [rev]);
ok(tl.timeline[0].revoked_from === 4, 'a genesis-szegmens revoked_from=4');
const revEarlier = s.buildKeyRevocation({ log_id: LOG, role: 'receipt', revoked_fingerprint: fpRc1,
  revoked_at_tree_size: 2 }, root.privateKey, T0);
const tl2 = s.buildKeyTimeline(Rc1.publicKey, [], 'receipt', root.publicKey, [rev, revEarlier]);
ok(tl2.timeline[0].revoked_from === 2, 'tobb revokacional a legkorabbi hatar gyoz');
const revUnknown = s.buildKeyRevocation({ log_id: LOG, role: 'receipt',
  revoked_fingerprint: 'sha256:' + 'a'.repeat(64), revoked_at_tree_size: 2 }, root.privateKey, T0);
const tl3 = s.buildKeyTimeline(Rc1.publicKey, [], 'receipt', root.publicKey, [revUnknown]);
ok(tl3.problems.some(p => /nem-letezo/.test(p)) && tl3.timeline[0].revoked_from == null,
  'nem-letezo kulcs revokacioja jelzett, a timeline erintetlen');
const tlClean = s.buildKeyTimeline(Rc1.publicKey, [], 'receipt', root.publicKey);
ok(tlClean.timeline[0].revoked_from == null, 'revokacio nelkul nincs revoked_from (backward-kompat)');

// ───────────────────────────────────────────────────────────────────────────
// E2e elokeszites: rotalt log (Rc1 1..3, Rc2 4..6; sth: A 1..3, B 4..6)
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

(async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-rev-'));
  const sthSucc = s.buildKeySuccession({ log_id: LOG, role: 'sth',
    predecessor_fingerprint: s.keyFingerprint(A.publicKey), successor_public_key: B.publicKey,
    effective_from_tree_size: 4, reason: 'compromise' }, root.privateKey, T0);
  const recSucc = s.buildKeySuccession({ log_id: LOG, role: 'receipt',
    predecessor_fingerprint: fpRc1, successor_public_key: Rc2.publicKey,
    effective_from_tree_size: 4, reason: 'compromise' }, root.privateKey, T0);
  // a kompromittalt Rc1-et a rotacio hataran revokaljuk (tipikus parositas)
  const recRev = s.buildKeyRevocation({ log_id: LOG, role: 'receipt',
    revoked_fingerprint: fpRc1, revoked_at_tree_size: 4, reason: 'compromise' }, root.privateKey, T0);

  async function buildLog(dir) {
    const receiptsPath = path.join(dir, 'receipts.jsonl');
    const base = { receiptsPath, sthPath: path.join(dir, 'sth.jsonl'),
      anchorsPath: path.join(dir, 'anchors.jsonl'), backends: ['local'], logId: LOG, now: T0 };
    const run1 = makeRun(Rc1.privateKey, null, 'RUN1');
    fs.writeFileSync(receiptsPath, run1.receipts.map(r => JSON.stringify(r)).join('\n') + '\n');
    await runAnchor({ ...base, privateKeyPem: A.privateKey });
    const run2 = makeRun(Rc2.privateKey, run1.workflowHash, 'RUN2');
    fs.appendFileSync(receiptsPath, run2.receipts.map(r => JSON.stringify(r)).join('\n') + '\n');
    await runAnchor({ ...base, privateKeyPem: B.privateKey, succession: sthSucc });
    return base;
  }
  function writeAux(dir, revs) {
    const trPath = path.join(dir, 'trust-root.json');
    fs.writeFileSync(trPath, JSON.stringify(trustRoot) + '\n');
    const succPath = path.join(dir, 'successions.jsonl');
    fs.writeFileSync(succPath, JSON.stringify(recSucc) + '\n');
    const revPath = path.join(dir, 'revocations.jsonl');
    fs.writeFileSync(revPath, revs.map(x => JSON.stringify(x)).join('\n') + '\n');
    const keyPath = path.join(dir, 'rc1.pem');
    fs.writeFileSync(keyPath, Rc1.publicKey);
    return { trPath, succPath, revPath, keyPath };
  }
  function runVerifier(cmdName, dir, aux) {
    const script = cmdName === 'node' ? 'axr-verify.js' : 'axr_verify.py';
    const args = [path.join(__dirname, script),
      path.join(dir, 'receipts.jsonl'), aux.keyPath,
      path.join(dir, 'sth.jsonl'), path.join(dir, 'anchors.jsonl'),
      '--trust-root', aux.trPath, '--successions', aux.succPath, '--revocations', aux.revPath];
    try { execFileSync(cmdName, args, { stdio: 'pipe' }); return 0; }
    catch (e) { return e.status == null ? -1 : e.status; }
  }

  // ─────────────────────────────────────────────────────────────────────────
  section('3. A 3-szintu szabaly a verifierekben');
  const dirA = fs.mkdtempSync(path.join(tmp, 'a-'));
  const logA = await buildLog(dirA);
  const auxA = writeAux(dirA, [recRev]);
  ok(runVerifier('node', dirA, auxA) === 0,
    'anchorolt pre-boundary receiptek + revokacio -> JS exit 0 (a tanusitott mult ervenyes)');
  if (PYTHON) ok(runVerifier(PYTHON, dirA, auxA) === 0, 'Python: ugyanez exit 0 (cross-impl)');
  // bizonyitek nelkuli pre-boundary: egy Rc1-es receipt anchor_ref-jet toroljuk
  const dirB = fs.mkdtempSync(path.join(tmp, 'b-'));
  const logB = await buildLog(dirB);
  const auxB = writeAux(dirB, [recRev]);
  const recsB = fs.readFileSync(logB.receiptsPath, 'utf8').trim().split('\n').map(JSON.parse);
  delete recsB[0].anchor_ref; // pre-boundary, Rc1-alairt, bizonyitek nelkul
  fs.writeFileSync(logB.receiptsPath, recsB.map(r => JSON.stringify(r)).join('\n') + '\n');
  ok(runVerifier('node', dirB, auxB) === 1,
    'bizonyitek nelkuli pre-boundary receipt + revokacio -> JS exit 1 (fail-closed)');
  if (PYTHON) ok(runVerifier(PYTHON, dirB, auxB) === 1, 'Python: ugyanez exit 1');
  // kontroll: revokacio NELKUL az anchor_ref-mentes receipt csak "fuggoben"
  const auxB2 = writeAux(dirB, []);
  fs.writeFileSync(auxB2.revPath, ''); // ures revokacio-fajl helyett: nincs flag
  function runVerifierNoRev(cmdName, dir, aux) {
    const script = cmdName === 'node' ? 'axr-verify.js' : 'axr_verify.py';
    const args = [path.join(__dirname, script),
      path.join(dir, 'receipts.jsonl'), aux.keyPath,
      path.join(dir, 'sth.jsonl'), path.join(dir, 'anchors.jsonl'),
      '--trust-root', aux.trPath, '--successions', aux.succPath];
    try { execFileSync(cmdName, args, { stdio: 'pipe' }); return 0; }
    catch (e) { return e.status == null ? -1 : e.status; }
  }
  ok(runVerifierNoRev('node', dirB, auxB2) === 0,
    'kontroll: revokacio nelkul ugyanez a log exit 0 (a szigor a revokaciobol jon)');
  // hatar utani Rc1-alairt receipt: a run2 elso lepeset Rc1-gyel irjuk ujra ala
  const dirC = fs.mkdtempSync(path.join(tmp, 'c-'));
  const logC = await buildLog(dirC);
  const auxC = writeAux(dirC, [recRev]);
  const recsC = fs.readFileSync(logC.receiptsPath, 'utf8').trim().split('\n').map(JSON.parse);
  recsC[3] = sign(recsC[3], Rc1.privateKey); // 4. levelpozicio = hatar utani
  fs.writeFileSync(logC.receiptsPath, recsC.map(r => JSON.stringify(r)).join('\n') + '\n');
  ok(runVerifier('node', dirC, auxC) === 1, 'hatar utani Rc1-alairas -> JS exit 1 (KEY_REVOKED)');
  if (PYTHON) ok(runVerifier(PYTHON, dirC, auxC) === 1, 'Python: ugyanez exit 1');

  // ─────────────────────────────────────────────────────────────────────────
  section('4. Monitor: sth-revokacio');
  // a B (utod) sth-kulcsot revokaljuk tree_size 5-tol -> a 6-os STH sertes
  const sthRev = s.buildKeyRevocation({ log_id: LOG, role: 'sth',
    revoked_fingerprint: s.keyFingerprint(B.publicKey), revoked_at_tree_size: 5,
    reason: 'compromise' }, root.privateKey, T0);
  const dirM = fs.mkdtempSync(path.join(tmp, 'm-'));
  const logM = await buildLog(dirM);
  const resM = pollMonitor({ sthPath: logM.sthPath, publicKeyPem: A.publicKey,
    statePath: path.join(dirM, 'mon.json'), receiptsPath: logM.receiptsPath,
    trustRoot, revocations: [sthRev], now: T0 });
  ok(!resM.ok && resM.violations.some(v => v.code === 'KEY_REVOKED'),
    'hatar (5) utani STH (tree_size=6) -> KEY_REVOKED');
  // pre-boundary STH-k onmagukban nem sertesek: hatar a 7 (minden STH alatta)
  const sthRevLate = s.buildKeyRevocation({ log_id: LOG, role: 'sth',
    revoked_fingerprint: s.keyFingerprint(B.publicKey), revoked_at_tree_size: 7,
    reason: 'precaution' }, root.privateKey, T0);
  const resM2 = pollMonitor({ sthPath: logM.sthPath, publicKeyPem: A.publicKey,
    statePath: path.join(dirM, 'mon2.json'), receiptsPath: logM.receiptsPath,
    trustRoot, revocations: [sthRevLate], now: T0 });
  ok(resM2.ok, 'minden STH a hatar elott -> nincs sertes (a tanusitott mult ervenyes)');
  // hamis revokacio -> REVOCATION_UNAUTHORIZED
  const forgedSthRev = s.buildKeyRevocation({ log_id: LOG, role: 'sth',
    revoked_fingerprint: s.keyFingerprint(B.publicKey), revoked_at_tree_size: 5 },
    fakeRoot.privateKey, T0);
  const resM3 = pollMonitor({ sthPath: logM.sthPath, publicKeyPem: A.publicKey,
    statePath: path.join(dirM, 'mon3.json'), receiptsPath: logM.receiptsPath,
    trustRoot, revocations: [forgedSthRev], now: T0 });
  ok(!resM3.ok && resM3.violations.some(v => v.code === 'REVOCATION_UNAUTHORIZED'),
    'hamis root-tal alairt revokacio -> REVOCATION_UNAUTHORIZED (DoS-kiserlet jelzett)');

  console.log(`\nOsszesen: ${pass} ok, ${fail} hiba` + (PYTHON ? '' : ' (Python esetek kihagyva)'));
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('VARATLAN HIBA:', e); process.exit(1); });
