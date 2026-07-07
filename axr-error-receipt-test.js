// ═══════════════════════════════════════════════════════════════════════════════
// AXR P2 - Error-path receipt (bukott futas is kap alairt, lancolt receiptet)
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-error-receipt-test.js
//
// Forras: nguyenthieutoan (n8n community forum) - a kemeny hiba (node throw /
// workflow error-out) ma signed receipt nelkul marad. Ez a generator
// LEFEDETTSEGET bovit (generateErrorReceipt), NEM a wire formatot: a hiba-receipt
// egy normal 'workflow' receipt WORKFLOW_ERROR status-szal + additiv 'error'
// blokkal, amit a meglevo verifier valtozatlanul elfogad.
//
// Mit ellenoriz:
//   1. standalone hiba-receipt (nincs elozmeny, nincs lepes) -> verifier 0 (JS+Py)
//   2. VEGYES log: happy futas + hiba-futas EGY folytonos lancban -> verifier 0
//   3. struktura: WORKFLOW_ERROR, error-blokk mezok, chain_root_hash null lepesek
//      nelkul, helyes cross-run lancolas (previous_receipt_hash == chainHash(elozo))
//   4. ADATVEDELEM: csak message_hash kerul a logba, a cleartext uzenet SOHA
//   5. RED-TEAM: failed_node tamper / message_hash tamper / alairatlan hamis
//      receipt / idegen kulccsal alairt -> verifier 1 (JS+Py)
//   6. backward-kompat: a tiszta happy log valtozatlanul verifikal (error nelkul)
//
// Nulla kulso fuggoseg. Kilepesi kod: 0 ha minden zold, 1 ha barmi megbukik.
// ═══════════════════════════════════════════════════════════════════════════════

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const core = require('./axr-core');
const { generateReceipts, generateErrorReceipt } = require('./axr-generator');

let passed = 0;
function check(name, fn) {
  try { fn(); passed++; console.log(`  ok  - ${name}`); }
  catch (e) { console.log(`  HIBA - ${name}\n        ${e.message}`); process.exitCode = 1; }
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

const T0 = '2026-06-19T17:00:00.000Z';
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-err-'));

// operator alairo kulcspar + egy idegen kulcs (red-team)
const op = crypto.generateKeyPairSync('ed25519');
const opPriv = op.privateKey.export({ type: 'pkcs8', format: 'pem' });
const opPub = op.publicKey.export({ type: 'spki', format: 'pem' });
const pubPath = path.join(dir, 'pub.pem');
fs.writeFileSync(pubPath, opPub);
const evil = crypto.generateKeyPairSync('ed25519');
const evilPriv = evil.privateKey.export({ type: 'pkcs8', format: 'pem' });

// ── verifier-futtatas (JS + opcionalisan Python), exit-kodot ad vissza ─────────
function verify(cmd, logPath) {
  const script = cmd === 'node' ? 'axr-verify.js' : 'axr_verify.py';
  try { execFileSync(cmd, [path.join(__dirname, script), logPath, pubPath], { stdio: 'pipe' }); return 0; }
  catch (e) { return e.status == null ? -1 : e.status; }
}
function writeLog(name, records) {
  const p = path.join(dir, name);
  fs.writeFileSync(p, records.map(r => JSON.stringify(r)).join('\n') + '\n');
  return p;
}

// ── Realisztikus happy futas a generatorbol (a vegyes-lanc teszthez) ───────────
const webhookBody = {
  name: 'Teszt Elek', email: 'teszt.elek@example.com', phone: '+36301234567',
  date: '2026-06-15', totalDuration: 120, slotStartTime: '10:00',
  locationData: { city: 'Budapest' }, validation: { hasItems: true }
};
const brainClean = {
  available: true, status: 'SLOT_AVAILABLE',
  cluster: { id: 'BUDAPEST', country: 'HU' },
  slot: { startTime: '10:00', endTime: '12:00' },
  calendar: { travelBufferApplied: 30 }
};
const nodeOut = {
  'Normalize Payload - HU': [{ body: webhookBody, originalPayload: webhookBody, __axr_input: [{ body: webhookBody }] }],
  'Check Day Schedule': [{ id: 'e1', summary: 'x', __axr_input: [{ q: 1 }] }],
  'The Brain (Logic)': [{ ...brainClean, __axr_input: [{ events: 1 }] }],
  'Fresh Calendar Check': [{ id: 'e1', __axr_input: [{ y: 1 }] }],
  'Slot Still Free?': [{ slotFree: true, __axr_input: [{ id: 'e1' }] }],
  'Create Booking': [{ id: 'new', htmlLink: 'h', __axr_input: [{ slotFree: true }] }]
};
const happyCtx = {
  get: n => nodeOut[n] || null,
  normalizedBody: webhookBody, rawWebhookBody: webhookBody, brainOutput: brainClean,
  prevWorkflowHash: null, privateKeyPem: opPriv,
  triggerTimestamp: T0, completionTimestamp: T0, stepTimestamp: () => T0
};
const happy = generateReceipts(happyCtx);

// A bukott futas hibauzenete SZANDEKOSAN tartalmaz PII-szeru cleartextet
const SECRET_MSG = 'Calendar API 500 for teszt.elek@example.com (booking 2026-06-15)';

function makeError(prevHash, overrides) {
  return generateErrorReceipt(Object.assign({
    error: { failed_node: 'Create Booking', error_class: 'NodeApiError',
             message: SECRET_MSG, execution_id: 'exec-123', occurred_at: T0 },
    privateKeyPem: opPriv, rawWebhookBody: webhookBody,
    prevWorkflowHash: prevHash, triggerTimestamp: T0, completionTimestamp: T0
  }, overrides || {})).workflowReceipt;
}

// ── 1. standalone hiba-receipt (nincs elozmeny, nincs lepes) ────────────────────
const solo = makeError(null);
const soloLog = writeLog('solo.jsonl', [solo]);
check('standalone hiba-receipt: JS verifier elfogadja (exit 0)', () => assert.strictEqual(verify('node', soloLog), 0));
if (PYTHON) check('standalone hiba-receipt: Python verifier elfogadja (cross-impl)', () => assert.strictEqual(verify(PYTHON, soloLog), 0));

// ── 3. struktura ────────────────────────────────────────────────────────────────
check('final_status = WORKFLOW_ERROR', () => assert.strictEqual(solo.outcome.final_status, 'WORKFLOW_ERROR'));
check('outcome.available = false', () => assert.strictEqual(solo.outcome.available, false));
check('error-blokk mezoi jelen vannak', () => {
  assert.strictEqual(solo.error.failed_node, 'Create Booking');
  assert.strictEqual(solo.error.error_class, 'NodeApiError');
  assert.strictEqual(solo.error.execution_id, 'exec-123');
  assert.match(solo.error.message_hash, /^sha256:[0-9a-f]{64}$/);
});
check('lepesek nelkul: chain_root_hash null es step_chain ures', () => {
  assert.strictEqual(solo.chain_root_hash, null);
  assert.deepStrictEqual(solo.step_chain, []);
});
check('a hiba-receipt alairasa ervenyes (op kulcs)', () => assert.ok(core.verifyReceipt(solo, opPub)));

// ── 4. ADATVEDELEM: csak message_hash, cleartext SOHA ──────────────────────────
check('message_hash == sha256(cleartext uzenet)', () => assert.strictEqual(solo.error.message_hash, core.sha256(SECRET_MSG)));
check('a cleartext hibauzenet SEHOL nincs a receiptben', () => {
  const serialized = JSON.stringify(solo);
  assert.ok(!serialized.includes(SECRET_MSG), 'cleartext uzenet beszivargott a logba');
  assert.ok(!serialized.includes('teszt.elek@example.com'), 'email cleartext beszivargott');
});

// ── 2. VEGYES log: happy futas + hiba-futas egy folytonos lancban ──────────────
const errAfterHappy = makeError(happy.workflowReceiptHash);
const mixedLog = writeLog('mixed.jsonl', [...happy.stepReceipts, happy.workflowReceipt, errAfterHappy]);
check('vegyes (happy + error) log: JS verifier elfogadja (exit 0)', () => assert.strictEqual(verify('node', mixedLog), 0));
if (PYTHON) check('vegyes log: Python verifier elfogadja (cross-impl)', () => assert.strictEqual(verify(PYTHON, mixedLog), 0));
check('a hiba-futas previous_receipt_hash-e a happy workflow chainHash-e', () =>
  assert.strictEqual(errAfterHappy.previous_receipt_hash, core.chainHash(happy.workflowReceipt)));

// ket egymast koveto hiba-futas is folytonosan lancol
const err1 = makeError(null);
const err2 = makeError(core.chainHash(err1));
const twoErrLog = writeLog('twoerr.jsonl', [err1, err2]);
check('ket egymast koveto hiba-receipt folytonosan lancol (exit 0)', () => assert.strictEqual(verify('node', twoErrLog), 0));

// ── 6. backward-kompat: tiszta happy log valtozatlanul verifikal ───────────────
const happyLog = writeLog('happy.jsonl', [...happy.stepReceipts, happy.workflowReceipt]);
check('tiszta happy log (error nelkul) valtozatlanul verifikal', () => assert.strictEqual(verify('node', happyLog), 0));

// ── 5. RED-TEAM: minden tamper-ut elbukik (JS + Python) ────────────────────────
function tamperLog(name, mutate) {
  const recs = [solo].map(r => JSON.parse(JSON.stringify(r)));
  mutate(recs);
  return writeLog(name, recs);
}
// a) failed_node tamper alairas utan
const tNode = tamperLog('t-node.jsonl', recs => { recs[0].error.failed_node = 'The Brain (Logic)'; });
check('RED: failed_node tamper -> JS verifier elutasit (exit 1)', () => assert.strictEqual(verify('node', tNode), 1));
if (PYTHON) check('RED: failed_node tamper -> Python elutasit (cross-impl)', () => assert.strictEqual(verify(PYTHON, tNode), 1));
// b) message_hash tamper
const tMsg = tamperLog('t-msg.jsonl', recs => { recs[0].error.message_hash = core.sha256('mas uzenet'); });
check('RED: message_hash tamper -> JS verifier elutasit (exit 1)', () => assert.strictEqual(verify('node', tMsg), 1));
if (PYTHON) check('RED: message_hash tamper -> Python elutasit (cross-impl)', () => assert.strictEqual(verify(PYTHON, tMsg), 1));
// c) final_status tamper (a hiba elrejtese)
const tStatus = tamperLog('t-status.jsonl', recs => { recs[0].outcome.final_status = 'SLOT_AVAILABLE'; });
check('RED: final_status tamper (hiba elrejtese) -> JS elutasit (exit 1)', () => assert.strictEqual(verify('node', tStatus), 1));
// d) alairatlan hamis hiba-receipt
const tUnsigned = tamperLog('t-unsigned.jsonl', recs => { delete recs[0].signature; });
check('RED: alairatlan hiba-receipt -> JS elutasit (exit 1)', () => assert.strictEqual(verify('node', tUnsigned), 1));
// e) idegen kulccsal alairt hiba-receipt
const forged = makeError(null, { privateKeyPem: evilPriv });
const forgedLog = writeLog('forged.jsonl', [forged]);
check('RED: idegen kulccsal alairt hiba-receipt -> JS elutasit (exit 1)', () => assert.strictEqual(verify('node', forgedLog), 1));
if (PYTHON) check('RED: idegen kulccsal alairt -> Python elutasit (cross-impl)', () => assert.strictEqual(verify(PYTHON, forgedLog), 1));

// ── kotelezo kulcs-guard ───────────────────────────────────────────────────────
check('generateErrorReceipt privateKeyPem nelkul dob', () =>
  assert.throws(() => generateErrorReceipt({ error: {} }), /privateKeyPem kotelezo/));

console.log(`\nOsszesen: ${passed} ok` + (PYTHON ? '' : '  (Python esetek kihagyva - nincs python3)'));
