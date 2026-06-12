// ═══════════════════════════════════════════════════════════════════════════════
// AXR 0.7 - sidecar control-commitment teszt
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-anchor-control-test.js
//
// Mit ellenoriz:
//   1. Backward-kompat: controlPath nelkul az STH valtozatlan (nincs
//      control_root_hash/control_size, axr_version 0.3)
//   2. controlPath + controlTrustRoot: az STH commitol; a commitment a
//      tenyleges control log ellen helyes (control.checkSthCommitment ok)
//   3. Ures control log: control_size=0 explicit commitment (az "meg nincs
//      governance-esemeny" is bizonyitott)
//   4. Inkrementalis: a control log bovul -> a kovetkezo STH nagyobb
//      control_size-t commitol, append-only konzisztens
//   5. Red-team: ervenytelen control-rekord (hamis root) -> a sidecar DOB
//      (nem anchorol ervenytelen governance-anyagot); controlTrustRoot nelkul
//      a controlPath dob
//
// Nulla kulso fuggoseg.  Kilepesi kod: 0 zold, 1 hiba.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const axr = require('./axr-core');
const s = require('./axr-succession');
const c = require('./axr-control');
const { runAnchor } = require('./axr-anchor');

let pass = 0, fail = 0;
function ok(cond, name) { if (cond) { pass++; } else { fail++; console.log('  FAIL: ' + name); } }
function section(t) { console.log('\n' + t); }

function genKey() {
  const kp = crypto.generateKeyPairSync('ed25519');
  return { privateKey: kp.privateKey.export({ type: 'pkcs8', format: 'pem' }),
           publicKey: kp.publicKey.export({ type: 'spki', format: 'pem' }) };
}
const T0 = () => '2026-06-12T15:00:00.000Z';
const LOG = 'axr:anchor-control:v1';
const root = genKey(), A = genKey(), B = genKey(), Rc1 = genKey(), Rc2 = genKey(), fakeRoot = genKey();

const trustRoot = s.buildTrustRoot({ providers: [],
  logs: [{ log_id: LOG, genesis: { sth: A.publicKey, receipt: Rc1.publicKey } }] },
  root.privateKey, root.publicKey, T0);
const succRec = s.buildKeySuccession({ log_id: LOG, role: 'receipt',
  predecessor_fingerprint: s.keyFingerprint(Rc1.publicKey), successor_public_key: Rc2.publicKey,
  effective_from_tree_size: 4 }, root.privateKey, T0);
const rev = s.buildKeyRevocation({ log_id: LOG, role: 'receipt',
  revoked_fingerprint: s.keyFingerprint(Rc1.publicKey), revoked_at_tree_size: 4 }, root.privateKey, T0);

let leafSeq = 0;
function appendLeaves(p, n) {
  const out = [];
  for (let i = 0; i < n; i++) { leafSeq++; out.push({ axr_version: '0.3', receipt_type: 'step',
    receipt_id: 'leaf-' + leafSeq, timestamp: T0(), io: { input_hash: axr.sha256('in-' + leafSeq) } }); }
  fs.appendFileSync(p, out.map(r => JSON.stringify(r)).join('\n') + '\n');
}
function readSths(p) { return fs.readFileSync(p, 'utf8').trim().split('\n').map(JSON.parse); }

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-anchctl-'));
  const receiptsPath = path.join(dir, 'receipts.jsonl');
  const sthPath = path.join(dir, 'sth.jsonl');
  const trPath = path.join(dir, 'trust-root.json');
  fs.writeFileSync(trPath, JSON.stringify(trustRoot) + '\n');
  fs.writeFileSync(receiptsPath, '');
  const base = { receiptsPath, sthPath, anchorsPath: path.join(dir, 'anchors.jsonl'),
    backends: ['local'], logId: LOG, now: T0 };

  // ─────────────────────────────────────────────────────────────────────────
  section('1. Backward-kompat: controlPath nelkul');
  appendLeaves(receiptsPath, 3);
  await runAnchor({ ...base, privateKeyPem: A.privateKey });
  const sth1 = readSths(sthPath)[0];
  ok(!('control_root_hash' in sth1) && !('control_size' in sth1) && sth1.axr_version === '0.3',
    'controlPath nelkul az STH valtozatlan (nincs control-mezo)');

  // ─────────────────────────────────────────────────────────────────────────
  section('2. controlPath + controlTrustRoot: commitment');
  const controlPath = path.join(dir, 'control.jsonl');
  fs.writeFileSync(controlPath, [succRec, rev].map(r => JSON.stringify(r)).join('\n') + '\n');
  appendLeaves(receiptsPath, 1);
  await runAnchor({ ...base, privateKeyPem: A.privateKey, controlPath, controlTrustRootPath: trPath });
  const sth2 = readSths(sthPath)[1];
  ok(sth2.control_size === 2 && typeof sth2.control_root_hash === 'string',
    'az STH commitol: control_size=2');
  const controlRecs = fs.readFileSync(controlPath, 'utf8').trim().split('\n').map(JSON.parse);
  ok(c.checkSthCommitment(sth2, controlRecs).ok, 'a commitment a tenyleges control log ellen helyes');
  ok(axr.verifyReceipt(sth2, A.publicKey), 'az STH alairasa fedi a control-mezoket (verifikal)');

  // ─────────────────────────────────────────────────────────────────────────
  section('3. Ures control log: control_size=0');
  const emptyControl = path.join(dir, 'empty-control.jsonl');
  fs.writeFileSync(emptyControl, '');
  const dir3 = fs.mkdtempSync(path.join(dir, 'e-'));
  const rp3 = path.join(dir3, 'receipts.jsonl'); fs.writeFileSync(rp3, '');
  const base3 = { receiptsPath: rp3, sthPath: path.join(dir3, 'sth.jsonl'),
    anchorsPath: path.join(dir3, 'anchors.jsonl'), backends: ['local'], logId: LOG, now: T0 };
  appendLeaves(rp3, 2);
  await runAnchor({ ...base3, privateKeyPem: A.privateKey, controlPath: emptyControl, controlTrustRootPath: trPath });
  const sthE = readSths(base3.sthPath)[0];
  ok(sthE.control_size === 0 && sthE.control_root_hash === c.controlRoot([]),
    'ures control log -> control_size=0 + ures-fa gyoker (a "nincs governance-esemeny" bizonyitott)');

  // ─────────────────────────────────────────────────────────────────────────
  section('4. Inkrementalis: a control log bovul');
  fs.appendFileSync(controlPath, JSON.stringify(s.buildKeySuccession({ log_id: LOG, role: 'sth',
    predecessor_fingerprint: s.keyFingerprint(A.publicKey), successor_public_key: B.publicKey,
    effective_from_tree_size: 6 }, root.privateKey, T0)) + '\n');
  appendLeaves(receiptsPath, 1);
  await runAnchor({ ...base, privateKeyPem: A.privateKey, controlPath, controlTrustRootPath: trPath });
  const sth3 = readSths(sthPath)[2];
  ok(sth3.control_size === 3, 'a kovetkezo STH a bovult keszletet commitolja (3)');
  const recs3 = fs.readFileSync(controlPath, 'utf8').trim().split('\n').map(JSON.parse);
  ok(c.checkControlConsistency(sth2, sth3, recs3).ok, 'a ket commitment kozott append-only konzisztens');

  // ─────────────────────────────────────────────────────────────────────────
  section('5. Red-team: ervenytelen control-rekord / hianyzo trust-root');
  const badControl = path.join(dir, 'bad-control.jsonl');
  fs.writeFileSync(badControl, JSON.stringify(s.buildKeySuccession({ log_id: LOG, role: 'receipt',
    predecessor_fingerprint: s.keyFingerprint(Rc1.publicKey), successor_public_key: Rc2.publicKey,
    effective_from_tree_size: 4 }, fakeRoot.privateKey, T0)) + '\n');
  appendLeaves(receiptsPath, 1);
  let threw = false;
  try { await runAnchor({ ...base, privateKeyPem: A.privateKey, controlPath: badControl, controlTrustRootPath: trPath }); }
  catch (e) { threw = /NEM verifikal/.test(e.message); }
  ok(threw, 'hamis root-tal alairt control-rekord -> a sidecar DOB (nem anchorol)');
  threw = false;
  try { await runAnchor({ ...base, privateKeyPem: A.privateKey, controlPath }); }
  catch (e) { threw = /controlTrustRoot/.test(e.message); }
  ok(threw, 'controlTrustRoot nelkul a controlPath -> dob (commit elotti verify kotelezo)');
  // a dobasok utan nem keletkezett uj STH a fo logban
  ok(readSths(sthPath).length === 3, 'a sikertelen futasok nem irtak STH-t');

  console.log(`\nOsszesen: ${pass} ok, ${fail} hiba`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('VARATLAN HIBA:', e); process.exit(1); });
