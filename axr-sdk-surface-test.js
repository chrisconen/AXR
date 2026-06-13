// ═══════════════════════════════════════════════════════════════════════════════
// AXR - publikus SDK-felulet pinning teszt (a fagyasztott felulet kikenyszeritese)
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-sdk-surface-test.js
//
// Mit ellenoriz:
//   1. require('./index.js') betolt, version a package.json-nal egyezik
//   2. A FAGYASZTOTT publikus felulet: minden dokumentalt top-level nev es
//      nevter-fuggveny letezik a vart tipussal (egy nev eltunese/atnevezese piros)
//   3. Top-level visszafele-kompat: a core nevei top-level is elerhetok
//   4. SMOKE: a teljes governance-ut az SDK-n KERESZTUL fut (sign->verify,
//      trust-root, witness_set + cosign + witness_revocation 2-szintu szabaly)
//
// A felulet additiv modon bovulhet (uj nevek), de a ITT pinnelt nevek 1.x-ben
// NEM tornek. Ha uj publikus API-t adsz, ide is vedd fel - kulonben a teszt
// nem vedi.  Kilepesi kod: 0 zold, 1 hiba.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const pkg = require('./package.json');
const axr = require('./index.js');

let pass = 0, fail = 0;
function ok(cond, name) { if (cond) { pass++; } else { fail++; console.log('  FAIL: ' + name); } }
function section(t) { console.log('\n' + t); }
function genKey() {
  const kp = crypto.generateKeyPairSync('ed25519');
  return { privateKey: kp.privateKey.export({ type: 'pkcs8', format: 'pem' }),
           publicKey: kp.publicKey.export({ type: 'spki', format: 'pem' }) };
}

// A FAGYASZTOTT felulet: top-level nevek + nevterenkent a kotelezo publikus fgv-ek.
const TOP_LEVEL_FN = ['canonicalize', 'sha256', 'signReceipt', 'sign', 'verifyReceipt', 'keyFingerprint', 'verify'];
const NAMESPACES = {
  core: ['canonicalize', 'sha256', 'signReceipt', 'verifyReceipt', 'chainHash', 'signablePart',
         'merkleRoot', 'merkleRootFromLeaves', 'inclusionProof', 'verifyInclusion',
         'consistencyProof', 'verifyConsistency', 'mmrAppend', 'mmrRoot',
         'buildTrustRoot', 'verifyTrustRoot', 'buildRedactable', 'redactField', 'verifyRedactable',
         'attestSideEffect', 'verifySideEffect'],
  governance: ['keyFingerprint', 'buildTrustRoot', 'buildQuorumTrustRoot', 'verifyTrustRoot',
               'verifyTrustRootChain', 'trustRootMode', 'buildKeySuccession', 'verifyKeySuccession',
               'buildKeyRevocation', 'verifyKeyRevocation', 'buildKeyTimeline', 'keyAtTreeSize',
               'buildWitnessSet', 'verifyWitnessSet', 'buildWitnessTimeline', 'witnessAt',
               'cosignWitness', 'assembleWitnessCosignatures', 'verifyWitnessCosignatures',
               'buildWitnessRevocation', 'verifyWitnessRevocation', 'revokedWitnessesAt'],
  anchor: ['runAnchor', 'runUpgrade'],
  monitor: ['pollMonitor', 'compareJournals'],
  control: ['verifyControlRecord', 'verifyControlLog', 'controlRoot', 'checkSthCommitment', 'checkControlConsistency'],
  ocsf: ['toDetectionFindings'],
  report: ['buildReportModel', 'renderHtml', 'renderJson'],
  generator: ['generateReceipts', 'generateReceiptsV3'],
  journalReceipts: ['buildJournalReceipts'],
  webhook: ['deliver']
};

// ───────────────────────────────────────────────────────────────────────────
section('1. Betoltes + version');
ok(typeof axr === 'object' && axr, 'require(./index.js) objektumot ad');
ok(axr.version === pkg.version && typeof axr.version === 'string' && axr.version.length > 0,
  'axr.version a package.json verziojaval egyezik (' + axr.version + ')');

// ───────────────────────────────────────────────────────────────────────────
section('2. Top-level fagyasztott nevek');
for (const fn of TOP_LEVEL_FN) ok(typeof axr[fn] === 'function', `top-level axr.${fn} fuggveny`);
ok(axr.sign === axr.signReceipt, 'axr.sign === axr.signReceipt (alias)');

// ───────────────────────────────────────────────────────────────────────────
section('3. Nevterek + kotelezo publikus fuggvenyek');
for (const [ns, fns] of Object.entries(NAMESPACES)) {
  ok(axr[ns] && typeof axr[ns] === 'object', `axr.${ns} nevter letezik`);
  for (const fn of fns) ok(axr[ns] && typeof axr[ns][fn] === 'function', `axr.${ns}.${fn} fuggveny`);
}
// a top-level core-nevek a core nevterrel azonos referenciak (visszafele-kompat)
ok(axr.merkleRoot === axr.core.merkleRoot && axr.canonicalize === axr.core.canonicalize,
  'a top-level core-nevek === a core nevter megfelelo nevei');

// ───────────────────────────────────────────────────────────────────────────
section('4. SMOKE: governance-ut az SDK-n keresztul');
const T0 = () => '2026-06-13T14:00:00.000Z';
const LOG = 'axr:sdk:v1';
const root = genKey(), op = genKey(), W1 = genKey(), W2 = genKey();

// 4a. sign -> verify egy minimalis receipten
const rc = { axr_version: '0.3', receipt_type: 'step', receipt_id: 'r1', timestamp: T0(),
  step: { node_name: 'n', node_type: 't', kind: 'deterministic', deterministic: true, model: null },
  io: { input_hash: axr.sha256('x'), output_hash: null, input_summary: {}, decision: null },
  inputs: [], approval: null, previous_receipt_hash: null };
rc.signature = axr.sign(rc, op.privateKey);
ok(axr.verifyReceipt(rc, op.publicKey), 'sign -> verifyReceipt OK az SDK-n at');
rc.io.input_summary.tamper = 'x';
ok(!axr.verifyReceipt(rc, op.publicKey), 'tamperelt receipt -> verifyReceipt false');

// 4b. trust-root + witness_set + cosign + witness_revocation 2-szintu szabaly
const tr = axr.governance.buildTrustRoot({ providers: [],
  logs: [{ log_id: LOG, genesis: { sth: op.publicKey, receipt: op.publicKey } }] },
  root.privateKey, root.publicKey, T0);
ok(axr.governance.verifyTrustRoot(tr).ok, 'trust-root build+verify az SDK-n at');
const ws = axr.governance.buildWitnessSet({ log_id: LOG, witness_threshold: 2, effective_from_tree_size: 1,
  witnesses: [{ name: 'a', public_key: W1.publicKey }, { name: 'b', public_key: W2.publicKey }] }, root.privateKey, T0);
const W2fp = axr.keyFingerprint(W2.publicKey);
const wrev = axr.governance.buildWitnessRevocation({ log_id: LOG, revoked_fingerprint: W2fp, revoked_at_tree_size: 6 }, root.privateKey);
ok(axr.governance.verifyWitnessRevocation(wrev, tr).ok, 'witness_revocation build+verify az SDK-n at');
const wtl = axr.governance.buildWitnessTimeline([ws], tr, [wrev]);
ok(axr.governance.revokedWitnessesAt(wtl.revocations, 6).has(W2fp), '2-szintu szabaly elerheto az SDK-n at (tree_size=6: W2 revokalt)');
// control-log verify az SDK-n at
ok(axr.control.verifyControlRecord(ws, tr, LOG).ok, 'control.verifyControlRecord OK az SDK-n at');

console.log(`\nOsszesen: ${pass} ok, ${fail} hiba`);
process.exit(fail ? 1 : 0);
