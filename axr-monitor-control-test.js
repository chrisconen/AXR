// ═══════════════════════════════════════════════════════════════════════════════
// AXR 0.7 - monitor control-log fogyasztas teszt
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-monitor-control-test.js
//
// Mit ellenoriz:
//   1. Happy path: control-commitmentes log + teljes control log -> nincs sertes,
//      a journal pinneli a control_size-t/gyokeret
//   2. CONTROL_LAG -> CONTROL_WITHHELD eszkalacio: rovidebb control log elso
//      pollnal megjegyzes, masodiknal sertes
//   3. CONTROL_ROOT_MISMATCH: a publikalt control log nem egyezik a commitolt
//      gyokerrel
//   4. CONTROL_NON_APPEND_ONLY: a commitolt control_size csokken ket poll kozott
//   5. CONTROL_DOWNGRADE: ket log, az ujabb (nagyobb fa) nem commitol
//   6. Ervenytelen control-rekord -> KEY_CHANGED_UNAUTHORIZED (ugyanaz a kod)
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
const T0 = () => '2026-06-12T16:00:00.000Z';
const LOG = 'axr:mon-control:v1';
const root = genKey(), A = genKey(), Rc1 = genKey(), Rc2 = genKey(), fakeRoot = genKey();

const trustRoot = s.buildTrustRoot({ providers: [],
  logs: [{ log_id: LOG, genesis: { sth: A.publicKey, receipt: Rc1.publicKey } }] },
  root.privateKey, root.publicKey, T0);
const trustRootRecords = [trustRoot];
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

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-monctl-'));
  const receiptsPath = path.join(dir, 'receipts.jsonl');
  const sthPath = path.join(dir, 'sth.jsonl');
  const trPath = path.join(dir, 'trust-root.json');
  const controlPath = path.join(dir, 'control.jsonl');
  fs.writeFileSync(trPath, JSON.stringify(trustRoot) + '\n');
  fs.writeFileSync(receiptsPath, '');
  fs.writeFileSync(controlPath, [succRec, rev].map(r => JSON.stringify(r)).join('\n') + '\n');
  const base = { receiptsPath, sthPath, anchorsPath: path.join(dir, 'anchors.jsonl'),
    backends: ['local'], logId: LOG, now: T0 };
  const controlRecs = () => fs.readFileSync(controlPath, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);

  // ket commitolt STH: 3 level @ control_size 2, majd +1 level @ control_size 2
  appendLeaves(receiptsPath, 3);
  await runAnchor({ ...base, privateKeyPem: A.privateKey, controlPath, controlTrustRootPath: trPath });

  // ─────────────────────────────────────────────────────────────────────────
  section('1. Happy path');
  const st1 = path.join(dir, 'mon1.json');
  const res1 = pollMonitor({ sthPath, publicKeyPem: A.publicKey, statePath: st1,
    receiptsPath, trustRoot: trustRootRecords, control: controlRecs(), now: T0 });
  ok(res1.ok, 'control-commitmentes log + teljes control log -> nincs sertes: ' + JSON.stringify(res1.violations));
  const j1 = JSON.parse(fs.readFileSync(st1, 'utf8'));
  ok(j1.control_max_size === 2 && j1.control_committed === true, 'journal pinneli a control_size-t (2)');

  // ─────────────────────────────────────────────────────────────────────────
  section('2. CONTROL_LAG -> CONTROL_WITHHELD eszkalacio');
  const stLag = path.join(dir, 'mon-lag.json');
  const partial = [succRec]; // a commitolt 2 helyett csak 1
  const resLag1 = pollMonitor({ sthPath, publicKeyPem: A.publicKey, statePath: stLag,
    receiptsPath, trustRoot: trustRootRecords, control: partial, now: T0 });
  ok(/CONTROL_LAG/.test(resLag1.notices.join(' | ')) && !codes(resLag1).includes('CONTROL_WITHHELD'),
    'elso poll: CONTROL_LAG megjegyzes, meg nincs WITHHELD');
  const resLag2 = pollMonitor({ sthPath, publicKeyPem: A.publicKey, statePath: stLag,
    receiptsPath, trustRoot: trustRootRecords, control: partial, now: T0 });
  ok(codes(resLag2).includes('CONTROL_WITHHELD'), 'masodik poll: CONTROL_WITHHELD sertes');

  // ─────────────────────────────────────────────────────────────────────────
  section('3. CONTROL_ROOT_MISMATCH');
  // a control log helyes hosszu, de a tartalom mas (a revokaciot kicsereljuk)
  const wrongRev = s.buildKeyRevocation({ log_id: LOG, role: 'receipt',
    revoked_fingerprint: s.keyFingerprint(Rc2.publicKey), revoked_at_tree_size: 9 }, root.privateKey, T0);
  const resMM = pollMonitor({ sthPath, publicKeyPem: A.publicKey, statePath: path.join(dir, 'mon-mm.json'),
    receiptsPath, trustRoot: trustRootRecords, control: [succRec, wrongRev], now: T0 });
  ok(codes(resMM).includes('CONTROL_ROOT_MISMATCH'),
    'mas tartalmu (de helyes hosszu) control log -> CONTROL_ROOT_MISMATCH');

  // ─────────────────────────────────────────────────────────────────────────
  section('4. CONTROL_NON_APPEND_ONLY (zsugorodas ket poll kozott)');
  const stShrink = path.join(dir, 'mon-shrink.json');
  pollMonitor({ sthPath, publicKeyPem: A.publicKey, statePath: stShrink,
    receiptsPath, trustRoot: trustRootRecords, control: controlRecs(), now: T0 });
  // a kovetkezo pollnal egy zsugoritott STH-folyamot mutatunk: ujraepitjuk a
  // logot kisebb control-keszlettel egy MASIK konyvtarban, de UGYANAZZAL a
  // journallal -> a commitolt control_size csokkenne. Egyszerubb: a journal
  // control_max_size-t kezzel nagyobbra allitjuk, majd pollozunk.
  const jShrink = JSON.parse(fs.readFileSync(stShrink, 'utf8'));
  jShrink.control_max_size = 99;
  fs.writeFileSync(stShrink, JSON.stringify(jShrink));
  const resShrink = pollMonitor({ sthPath, publicKeyPem: A.publicKey, statePath: stShrink,
    receiptsPath, trustRoot: trustRootRecords, control: controlRecs(), now: T0 });
  ok(codes(resShrink).includes('CONTROL_NON_APPEND_ONLY'),
    'a journalban pinnelt control_size > a mostani -> CONTROL_NON_APPEND_ONLY');

  // ─────────────────────────────────────────────────────────────────────────
  section('5. CONTROL_DOWNGRADE');
  // uj log: elso STH commitol, masodik (nagyobb fa) NEM. A masodik STH-t
  // control nelkul horgonyozzuk ugyanabba a sth-fajlba.
  const dir5 = fs.mkdtempSync(path.join(dir, 'd-'));
  const rp5 = path.join(dir5, 'receipts.jsonl'); fs.writeFileSync(rp5, '');
  const sp5 = path.join(dir5, 'sth.jsonl');
  const cp5 = path.join(dir5, 'control.jsonl');
  fs.writeFileSync(cp5, JSON.stringify(succRec) + '\n');
  const base5 = { receiptsPath: rp5, sthPath: sp5, anchorsPath: path.join(dir5, 'anchors.jsonl'),
    backends: ['local'], logId: LOG, now: T0 };
  appendLeaves(rp5, 2);
  await runAnchor({ ...base5, privateKeyPem: A.privateKey, controlPath: cp5, controlTrustRootPath: trPath });
  appendLeaves(rp5, 1);
  await runAnchor({ ...base5, privateKeyPem: A.privateKey }); // NINCS control -> downgrade
  const resDown = pollMonitor({ sthPath: sp5, publicKeyPem: A.publicKey, statePath: path.join(dir5, 'mon.json'),
    receiptsPath: rp5, trustRoot: trustRootRecords, control: [succRec], now: T0 });
  ok(codes(resDown).includes('CONTROL_DOWNGRADE'),
    'a nagyobb fa-meretu STH nem commitol, de korabbi igen -> CONTROL_DOWNGRADE');

  // ─────────────────────────────────────────────────────────────────────────
  section('5b. CONTROL_DOWNGRADE within-poll kozteso res (commit -> no -> commit)');
  // Meridian-review: a kozteso nem-commitolo STH-t is el kell kapni, nem csak
  // a legnagyobbat. Log: STH1 commitol, STH2 NEM, STH3 commitol.
  const dir5b = fs.mkdtempSync(path.join(dir, 'g-'));
  const rp5b = path.join(dir5b, 'receipts.jsonl'); fs.writeFileSync(rp5b, '');
  const sp5b = path.join(dir5b, 'sth.jsonl');
  const cp5b = path.join(dir5b, 'control.jsonl');
  fs.writeFileSync(cp5b, JSON.stringify(succRec) + '\n');
  const base5b = { receiptsPath: rp5b, sthPath: sp5b, anchorsPath: path.join(dir5b, 'anchors.jsonl'),
    backends: ['local'], logId: LOG, now: T0 };
  appendLeaves(rp5b, 2);
  await runAnchor({ ...base5b, privateKeyPem: A.privateKey, controlPath: cp5b, controlTrustRootPath: trPath }); // STH1 commit
  appendLeaves(rp5b, 1);
  await runAnchor({ ...base5b, privateKeyPem: A.privateKey }); // STH2 NEM commit (kozteso)
  appendLeaves(rp5b, 1);
  await runAnchor({ ...base5b, privateKeyPem: A.privateKey, controlPath: cp5b, controlTrustRootPath: trPath }); // STH3 commit
  const resGap = pollMonitor({ sthPath: sp5b, publicKeyPem: A.publicKey, statePath: path.join(dir5b, 'mon.json'),
    receiptsPath: rp5b, trustRoot: trustRootRecords, control: [succRec], now: T0 });
  ok(codes(resGap).includes('CONTROL_DOWNGRADE'),
    'a kozteso (nem legnagyobb) nem-commitolo STH is CONTROL_DOWNGRADE');

  // ─────────────────────────────────────────────────────────────────────────
  section('6. Ervenytelen control-rekord');
  const forged = s.buildKeySuccession({ log_id: LOG, role: 'sth',
    predecessor_fingerprint: s.keyFingerprint(A.publicKey), successor_public_key: Rc2.publicKey,
    effective_from_tree_size: 2 }, fakeRoot.privateKey, T0);
  const resBad = pollMonitor({ sthPath, publicKeyPem: A.publicKey, statePath: path.join(dir, 'mon-bad.json'),
    receiptsPath, trustRoot: trustRootRecords, control: [forged, succRec, rev], now: T0 });
  ok(codes(resBad).includes('KEY_CHANGED_UNAUTHORIZED'),
    'control logba csempeszett hamis succession -> KEY_CHANGED_UNAUTHORIZED');

  console.log(`\nOsszesen: ${pass} ok, ${fail} hiba`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('VARATLAN HIBA:', e); process.exit(1); });
