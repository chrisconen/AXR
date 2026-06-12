// ═══════════════════════════════════════════════════════════════════════════════
// AXR 0.7 - control-log core teszt
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-control-test.js
//
// Mit ellenoriz:
//   1. controlRoot: ures fa gyokere; determinisztikus; egyezik a core-eval
//   2. verifyControlRecord / verifyControlLog: root-verifikalt elfogad, hamis/
//      idegen-log/ismeretlen-tipus elutasit (single + kvorum + lanc horgony)
//   3. checkSthCommitment: nincs commitment; helyes commitment; rossz gyoker;
//      withheld (rovidebb log); hianyos (fel-mezo)
//   4. checkControlConsistency: append-only ok; zsugorodas; azonos meret eltero
//      gyoker; tort consistency
//
// Nulla kulso fuggoseg.  Kilepesi kod: 0 zold, 1 hiba.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const core = require('./axr-core');
const s = require('./axr-succession');
const c = require('./axr-control');

let pass = 0, fail = 0;
function ok(cond, name) { if (cond) { pass++; } else { fail++; console.log('  FAIL: ' + name); } }
function section(t) { console.log('\n' + t); }

function genKey() {
  const kp = crypto.generateKeyPairSync('ed25519');
  return { privateKey: kp.privateKey.export({ type: 'pkcs8', format: 'pem' }),
           publicKey: kp.publicKey.export({ type: 'spki', format: 'pem' }) };
}
const T0 = () => '2026-06-12T15:00:00.000Z';
const LOG = 'axr:control-test:v1';
const root = genKey(), A = genKey(), B = genKey(), Rc1 = genKey(), Rc2 = genKey(), fakeRoot = genKey();

const trustRoot = s.buildTrustRoot({ providers: [],
  logs: [{ log_id: LOG, genesis: { sth: A.publicKey, receipt: Rc1.publicKey } }] },
  root.privateKey, root.publicKey, T0);

const succSth = s.buildKeySuccession({ log_id: LOG, role: 'sth',
  predecessor_fingerprint: s.keyFingerprint(A.publicKey), successor_public_key: B.publicKey,
  effective_from_tree_size: 4 }, root.privateKey, T0);
const succRec = s.buildKeySuccession({ log_id: LOG, role: 'receipt',
  predecessor_fingerprint: s.keyFingerprint(Rc1.publicKey), successor_public_key: Rc2.publicKey,
  effective_from_tree_size: 4 }, root.privateKey, T0);
const rev = s.buildKeyRevocation({ log_id: LOG, role: 'receipt',
  revoked_fingerprint: s.keyFingerprint(Rc1.publicKey), revoked_at_tree_size: 4 }, root.privateKey, T0);

// ───────────────────────────────────────────────────────────────────────────
section('1. controlRoot');
ok(c.controlRoot([]) === core.merkleRootFromLeaves([]), 'ures fa gyokere = core ures gyoker');
const recs = [succSth, succRec, rev];
ok(c.controlRoot(recs) === core.merkleRootFromLeaves(recs.map(core.leafHash)),
  'control-gyoker = core Merkle a level-hash-ek felett');
ok(c.controlRoot(recs) === c.controlRoot(recs), 'determinisztikus');

// ───────────────────────────────────────────────────────────────────────────
section('2. verifyControlRecord / verifyControlLog');
ok(c.verifyControlRecord(succSth, trustRoot, LOG).ok, 'ervenyes succession (trust-root horgony)');
ok(c.verifyControlRecord(rev, root.publicKey, LOG).ok, 'ervenyes revokacio (PEM horgony)');
ok(!c.verifyControlRecord(succSth, trustRoot, 'masik:log').ok, 'idegen log_id -> elutasitva');
const forged = s.buildKeySuccession({ log_id: LOG, role: 'sth',
  predecessor_fingerprint: s.keyFingerprint(A.publicKey), successor_public_key: B.publicKey,
  effective_from_tree_size: 4 }, fakeRoot.privateKey, T0);
ok(!c.verifyControlRecord(forged, trustRoot, LOG).ok, 'hamis root-tal alairt -> elutasitva');
ok(!c.verifyControlRecord({ record_type: 'valami_mas', log_id: LOG }, trustRoot, LOG).ok,
  'ismeretlen record_type -> elutasitva');
const logRes = c.verifyControlLog(recs, trustRoot, LOG);
ok(logRes.ok && logRes.valid.length === 3, 'verifyControlLog: mind a 3 rekord ervenyes');
const mixed = c.verifyControlLog([succSth, forged, rev], trustRoot, LOG);
ok(!mixed.ok && mixed.valid.length === 2 && mixed.problems.some(p => /control\[1\]/.test(p)),
  'vegyes log: a hamis rekord jelzett, a tobbi valid');
// kvorum + lanc horgony
const Q1 = genKey(), Q2 = genKey(), Q3 = genKey();
const qTr = s.buildQuorumTrustRoot({ providers: [], root_keys: [Q1.publicKey, Q2.publicKey, Q3.publicKey],
  threshold: 2, logs: [{ log_id: LOG, genesis: { sth: A.publicKey, receipt: Rc1.publicKey } }] },
  [Q1.privateKey, Q2.privateKey], T0);
const succQ = s.buildQuorumKeySuccession({ log_id: LOG, role: 'sth',
  predecessor_fingerprint: s.keyFingerprint(A.publicKey), successor_public_key: B.publicKey,
  effective_from_tree_size: 4 }, [Q1.privateKey, Q3.privateKey], T0);
ok(c.verifyControlRecord(succQ, qTr, LOG).ok, 'kvorum-horgony: kvorum-rekord verifikal');
ok(c.verifyControlRecord(succQ, [qTr], LOG).ok, 'lanc-horgony (egy elemu) is mukodik');

// ───────────────────────────────────────────────────────────────────────────
section('3. checkSthCommitment');
ok(c.checkSthCommitment({ tree_size: 5 }, recs).committed === false,
  'nincs commitment-mezo -> committed=false, ok');
const goodRoot2 = c.controlRoot(recs.slice(0, 2));
ok(c.checkSthCommitment({ control_root_hash: goodRoot2, control_size: 2 }, recs).ok,
  'helyes commitment (elso 2 rekord)');
ok(!c.checkSthCommitment({ control_root_hash: 'sha256:' + '0'.repeat(64), control_size: 2 }, recs).ok,
  'rossz gyoker -> nem ok');
const wh = c.checkSthCommitment({ control_root_hash: c.controlRoot(recs), control_size: 5 }, recs);
ok(!wh.ok && wh.withheld, 'commitolt meret > rendelkezesre allo -> withheld');
ok(!c.checkSthCommitment({ control_root_hash: goodRoot2 }, recs).ok,
  'hianyos commitment (csak root, nincs size) -> nem ok');

// ───────────────────────────────────────────────────────────────────────────
section('4. checkControlConsistency');
const sth1 = { control_root_hash: c.controlRoot(recs.slice(0, 1)), control_size: 1 };
const sth2 = { control_root_hash: c.controlRoot(recs.slice(0, 3)), control_size: 3 };
ok(c.checkControlConsistency(sth1, sth2, recs).ok, 'append-only 1 -> 3: ok');
const shrink = c.checkControlConsistency(sth2, sth1, recs);
ok(!shrink.ok && shrink.problems.some(p => /zsugorodott/.test(p)), 'zsugorodas (3 -> 1) -> sertes');
const sameDiff = c.checkControlConsistency(
  { control_root_hash: c.controlRoot(recs.slice(0, 2)), control_size: 2 },
  { control_root_hash: 'sha256:' + '1'.repeat(64), control_size: 2 }, recs);
ok(!sameDiff.ok, 'azonos meret eltero gyoker -> sertes');
// tort consistency: a 3-fa gyokere helyett hamis
const broken = c.checkControlConsistency(sth1,
  { control_root_hash: 'sha256:' + '2'.repeat(64), control_size: 3 }, recs);
ok(!broken.ok, 'tort consistency (hamis cel-gyoker) -> sertes');

console.log(`\nOsszesen: ${pass} ok, ${fail} hiba`);
process.exit(fail ? 1 : 0);
