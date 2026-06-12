// ═══════════════════════════════════════════════════════════════════════════════
// AXR 0.5 - rotacion ativelo verifikacio (JS + Python verifier, cross-impl)
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-verify-succession-test.js   (a Python eseteket kihagyja,
//            ha nincs python3/python)
//
// Mit ellenoriz:
//   1. KONTROLL: a rotalt log a regi (egykulcsos) uton SERTES - ez motivalja
//      a 15. ellenorzest
//   2. --trust-root + --successions: a rotacion ativelo log EGYBEN ervenyes
//      (JS exit 0 ES Python exit 0 - cross-impl egyetertes)
//   3. Red-team: hatar-serto receipt (a regi korszak pozicioja az utod kulcsaval
//      alairva) -> mindket verifier elutasit
//   4. Red-team: hamis root-tal alairt receipt-succession -> elutasitva
//   5. Red-team: torzs-hamisitas a rotacio UTANI receipten -> elutasitva
//
// A logot a TERMELESI uton epitjuk (sign + runAnchor).  Kilepesi kod: 0/1.
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
  return {
    privateKey: kp.privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicKey: kp.publicKey.export({ type: 'spki', format: 'pem' })
  };
}

// Python interpreter felderites (mint a crossverify tesztben)
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

const T0 = () => '2026-06-12T00:00:00.000Z';
const LOG = 'axr:verify-succ-test:v1';

// Kulcsok: root, sthA/sthB (STH genesis + utod), recR1/recR2 (receipt genesis +
// utod), X (idegen), fakeRoot (tamado sajat "rootja")
const root = genKey(), sthA = genKey(), sthB = genKey();
const recR1 = genKey(), recR2 = genKey(), X = genKey(), fakeRoot = genKey();

const trustRoot = s.buildTrustRoot({
  providers: [],
  logs: [{ log_id: LOG, genesis: { sth: sthA.publicKey, receipt: recR1.publicKey } }]
}, root.privateKey, root.publicKey, T0);

const succSth = s.buildKeySuccession({
  log_id: LOG, role: 'sth', predecessor_fingerprint: s.keyFingerprint(sthA.publicKey),
  successor_public_key: sthB.publicKey, effective_from_tree_size: 4, reason: 'scheduled'
}, root.privateKey, T0);
const succRec = s.buildKeySuccession({
  log_id: LOG, role: 'receipt', predecessor_fingerprint: s.keyFingerprint(recR1.publicKey),
  successor_public_key: recR2.publicKey, effective_from_tree_size: 4, reason: 'scheduled'
}, root.privateKey, T0);

// Egy teljes workflow-futas (2 step + 1 workflow), a megadott kulccsal alairva.
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

// Egy rotalt log felepitese egy konyvtarba; visszaadja az eleresi utakat.
async function buildRotatedLog(dir, opts) {
  const o = opts || {};
  const receiptsPath = path.join(dir, 'receipts.jsonl');
  const base = { receiptsPath, sthPath: path.join(dir, 'sth.jsonl'),
    anchorsPath: path.join(dir, 'anchors.jsonl'), backends: ['local'], logId: LOG, now: T0 };
  // run1: R1 irja ala (levelek 1..3), sthA horgonyoz
  const run1 = makeRun(recR1.privateKey, null, 'RUN1');
  fs.writeFileSync(receiptsPath, run1.receipts.map(r => JSON.stringify(r)).join('\n') + '\n');
  await runAnchor({ ...base, privateKeyPem: sthA.privateKey });
  // run2: R2 irja ala (levelek 4..6), sthB horgonyoz, beagyazott sth-succession
  const run2 = makeRun((o.run2Key || recR2).privateKey, run1.workflowHash, 'RUN2');
  fs.appendFileSync(receiptsPath, run2.receipts.map(r => JSON.stringify(r)).join('\n') + '\n');
  await runAnchor({ ...base, privateKeyPem: sthB.privateKey, succession: o.sthSucc || succSth });
  return { ...base, run1, run2 };
}

function writeAux(dir, succs) {
  const trPath = path.join(dir, 'trust-root.json');
  fs.writeFileSync(trPath, JSON.stringify(trustRoot) + '\n');
  const succPath = path.join(dir, 'successions.jsonl');
  fs.writeFileSync(succPath, succs.map(x => JSON.stringify(x)).join('\n') + '\n');
  const keyPath = path.join(dir, 'rec-genesis.pem');
  fs.writeFileSync(keyPath, recR1.publicKey);
  return { trPath, succPath, keyPath };
}

function runJs(dir, aux, extra) {
  const args = [path.join(__dirname, 'axr-verify.js'),
    path.join(dir, 'receipts.jsonl'), aux.keyPath,
    path.join(dir, 'sth.jsonl'), path.join(dir, 'anchors.jsonl'), ...(extra || [])];
  try { execFileSync('node', args, { stdio: 'pipe' }); return 0; }
  catch (e) { return e.status == null ? -1 : e.status; }
}
function runPy(dir, aux, extra) {
  const args = [path.join(__dirname, 'axr_verify.py'),
    path.join(dir, 'receipts.jsonl'), aux.keyPath,
    path.join(dir, 'sth.jsonl'), path.join(dir, 'anchors.jsonl'), ...(extra || [])];
  try { execFileSync(PYTHON, args, { stdio: 'pipe' }); return 0; }
  catch (e) { return e.status == null ? -1 : e.status; }
}

(async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-vsucc-'));
  const mkdir = (n) => { const d = path.join(tmp, n); fs.mkdirSync(d); return d; };
  const succFlags = (aux) => ['--trust-root', aux.trPath, '--successions', aux.succPath];

  const dirGood = mkdir('good');
  const good = await buildRotatedLog(dirGood);
  const auxGood = writeAux(dirGood, [succRec]);

  // ─────────────────────────────────────────────────────────────────────────
  section('1. Kontroll: a rotalt log a regi egykulcsos uton sertes');
  ok(runJs(dirGood, auxGood) === 1, 'JS verifier trust-root nelkul: exit 1 (R2 alairasok buknak)');

  // ─────────────────────────────────────────────────────────────────────────
  section('2. Trust-root + successions: a rotacion ativelo log egyben ervenyes');
  ok(runJs(dirGood, auxGood, succFlags(auxGood)) === 0, 'JS verifier: exit 0');
  if (PYTHON) {
    ok(runPy(dirGood, auxGood, succFlags(auxGood)) === 0, 'Python verifier: exit 0 (cross-impl egyetertes)');
    ok(runPy(dirGood, auxGood) === 1, 'Python kontroll trust-root nelkul: exit 1');
  } else {
    console.log('  SKIP - nincs python3/python, a cross-impl esetek kihagyva');
  }

  // ─────────────────────────────────────────────────────────────────────────
  section('3. Red-team: hatar-serto alairas (regi korszak pozicio, utod kulcs)');
  // a run1 elso lepeset (1. levelpozicio, R1 korszaka) R2-vel irjuk ujra ala
  const dirB = mkdir('boundary');
  const bLog = await buildRotatedLog(dirB);
  const auxB = writeAux(dirB, [succRec]);
  const bReceipts = fs.readFileSync(bLog.receiptsPath, 'utf8').trim().split('\n').map(JSON.parse);
  bReceipts[0] = sign(bReceipts[0], recR2.privateKey); // tartalom valtozatlan, kulcs rossz korszak
  fs.writeFileSync(bLog.receiptsPath, bReceipts.map(r => JSON.stringify(r)).join('\n') + '\n');
  ok(runJs(dirB, auxB, succFlags(auxB)) === 1, 'JS: a hatar elotti pozicio R2-vel -> exit 1');
  if (PYTHON) ok(runPy(dirB, auxB, succFlags(auxB)) === 1, 'Python: ugyanez -> exit 1');

  // ─────────────────────────────────────────────────────────────────────────
  section('4. Red-team: hamis root-tal alairt receipt-succession');
  const forgedRec = s.buildKeySuccession({
    log_id: LOG, role: 'receipt', predecessor_fingerprint: s.keyFingerprint(recR1.publicKey),
    successor_public_key: X.publicKey, effective_from_tree_size: 4, reason: 'compromise'
  }, fakeRoot.privateKey, T0);
  const dirF = mkdir('forged');
  await buildRotatedLog(dirF, { run2Key: X });
  const auxF = writeAux(dirF, [forgedRec]);
  ok(runJs(dirF, auxF, succFlags(auxF)) === 1, 'JS: hamis succession + X alairasok -> exit 1');
  if (PYTHON) ok(runPy(dirF, auxF, succFlags(auxF)) === 1, 'Python: ugyanez -> exit 1');

  // ─────────────────────────────────────────────────────────────────────────
  section('5. Red-team: torzs-hamisitas a rotacio utani receipten');
  const dirT = mkdir('tamper');
  const tLog = await buildRotatedLog(dirT);
  const auxT = writeAux(dirT, [succRec]);
  const tReceipts = fs.readFileSync(tLog.receiptsPath, 'utf8').trim().split('\n').map(JSON.parse);
  const idx = tReceipts.findIndex(r => r.outcome && r.outcome.final_status === 'RUN2');
  tReceipts[idx].outcome.final_status = 'HAMISITVA'; // nincs ujra-alairas
  fs.writeFileSync(tLog.receiptsPath, tReceipts.map(r => JSON.stringify(r)).join('\n') + '\n');
  ok(runJs(dirT, auxT, succFlags(auxT)) === 1, 'JS: hamisitott R2-receipt -> exit 1');
  if (PYTHON) ok(runPy(dirT, auxT, succFlags(auxT)) === 1, 'Python: ugyanez -> exit 1');

  // ─────────────────────────────────────────────────────────────────────────
  section('6. Red-team: forked receipt-succession (ket root-alairt, azonos hatar)');
  // Mindket rekord ervenyesen root-alairt, de ugyanarra a hatarra mutatnak ->
  // fail-closed: az R2-vel alairt receiptek sem fogadhatok el (first-wins zarva)
  const forkRec = s.buildKeySuccession({
    log_id: LOG, role: 'receipt', predecessor_fingerprint: s.keyFingerprint(recR1.publicKey),
    successor_public_key: X.publicKey, effective_from_tree_size: 4, reason: 'fork'
  }, root.privateKey, T0);
  const dirFork = mkdir('fork');
  await buildRotatedLog(dirFork);
  const auxFork = writeAux(dirFork, [succRec, forkRec]);
  ok(runJs(dirFork, auxFork, succFlags(auxFork)) === 1, 'JS: forked succession -> exit 1 (fail-closed)');
  if (PYTHON) ok(runPy(dirFork, auxFork, succFlags(auxFork)) === 1, 'Python: ugyanez -> exit 1');

  // ─────────────────────────────────────────────────────────────────────────
  console.log(`\nOsszesen: ${pass} ok, ${fail} hiba` + (PYTHON ? '' : ' (Python esetek kihagyva)'));
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('VARATLAN HIBA:', e); process.exit(1); });
