// ═══════════════════════════════════════════════════════════════════════════════
// AXR 0.8 - witness core teszt (witness_set, cosignature, timeline)
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-witness-test.js
//
// Mit ellenoriz:
//   1. witness_set build/verify (single + kvorum), hamis root / idegen, struktura
//   2. witness-idovonal: aktiv keszlet tree_size szerint; ambiguous (azonos
//      effective_from) fail-closed
//   3. cosignature: a volatilis mezo NEM tori az operator-alairast es a lancot
//      (core P2); cosign -> assemble -> verifyWitnessCosignatures
//   4. verifyWitnessCosignatures fail-closed: nem-deklaralt / duplikalt /
//      rendezetlen / ervenytelen cosignature -> anomalia; threshold-alattisag
//      NEM anomalia (kulon validCount)
//
// Nulla kulso fuggoseg.  Kilepesi kod: 0 zold, 1 hiba.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const axr = require('./axr-core');
const s = require('./axr-succession');

let pass = 0, fail = 0;
function ok(cond, name) { if (cond) { pass++; } else { fail++; console.log('  FAIL: ' + name); } }
function section(t) { console.log('\n' + t); }

function genKey() {
  const kp = crypto.generateKeyPairSync('ed25519');
  return { privateKey: kp.privateKey.export({ type: 'pkcs8', format: 'pem' }),
           publicKey: kp.publicKey.export({ type: 'spki', format: 'pem' }) };
}
const T0 = () => '2026-06-13T10:00:00.000Z';
const LOG = 'axr:witness-test:v1';
const root = genKey(), op = genKey(), fakeRoot = genKey();
const W1 = genKey(), W2 = genKey(), W3 = genKey(), Wx = genKey();

const trustRoot = s.buildTrustRoot({ providers: [],
  logs: [{ log_id: LOG, genesis: { sth: op.publicKey, receipt: op.publicKey } }] },
  root.privateKey, root.publicKey, T0);

// ───────────────────────────────────────────────────────────────────────────
section('1. witness_set build/verify');
const ws = s.buildWitnessSet({ log_id: LOG, witness_threshold: 2, effective_from_tree_size: 1,
  witnesses: [{ name: 'auditor', public_key: W1.publicKey }, { name: 'customer', public_key: W2.publicKey },
              { name: 'consortium', public_key: W3.publicKey }] }, root.privateKey, T0);
ok(s.verifyWitnessSet(ws, root.publicKey).ok, 'witness_set verifikal (PEM horgony)');
ok(s.verifyWitnessSet(ws, trustRoot).ok, 'witness_set verifikal (trust-root horgony)');
ok(!s.verifyWitnessSet(ws, fakeRoot.publicKey).ok, 'idegen root -> elutasitva');
const wsTampered = JSON.parse(JSON.stringify(ws)); wsTampered.witness_threshold = 1;
ok(!s.verifyWitnessSet(wsTampered, root.publicKey).ok, 'utolag csokkentett threshold -> alairas bukik');
let buildThrew = false;
try { s.buildWitnessSet({ log_id: LOG, witness_threshold: 5, effective_from_tree_size: 1,
  witnesses: [{ public_key: W1.publicKey }] }, root.privateKey, T0); } catch (e) { buildThrew = true; }
ok(buildThrew, 'threshold > witnesses -> build dob');
// kvorum-alairt witness_set
const Q1 = genKey(), Q2 = genKey(), Q3 = genKey();
const qTr = s.buildQuorumTrustRoot({ providers: [], root_keys: [Q1.publicKey, Q2.publicKey, Q3.publicKey],
  threshold: 2, logs: [{ log_id: LOG, genesis: { sth: op.publicKey, receipt: op.publicKey } }] },
  [Q1.privateKey, Q2.privateKey], T0);
const wsQ = s.buildQuorumWitnessSet({ log_id: LOG, witness_threshold: 1, effective_from_tree_size: 1,
  witnesses: [{ public_key: W1.publicKey }] }, [Q1.privateKey, Q3.privateKey], T0);
ok(s.verifyWitnessSet(wsQ, qTr).ok, 'kvorum-alairt witness_set verifikal a kvorum-roottal');

// ───────────────────────────────────────────────────────────────────────────
section('2. witness-idovonal');
const ws2 = s.buildWitnessSet({ log_id: LOG, witness_threshold: 1, effective_from_tree_size: 10,
  witnesses: [{ public_key: W1.publicKey }, { public_key: W2.publicKey }] }, root.privateKey, T0);
const tl = s.buildWitnessTimeline([ws, ws2], root.publicKey);
ok(tl.problems.length === 0 && tl.timeline.length === 2, 'ket szegmens, nincs problema');
ok(s.witnessAt(tl.timeline, 5).threshold === 2, 'tree_size 5 -> elso keszlet (threshold 2)');
ok(s.witnessAt(tl.timeline, 15).threshold === 1, 'tree_size 15 -> masodik keszlet (threshold 1)');
ok(s.witnessAt(tl.timeline, 0) === null, 'tree_size 0 (hatar elott) -> nincs aktiv keszlet');
// ambiguous: ket ELTERO keszlet azonos effective_from-ra -> fail-closed
const wsAmb = s.buildWitnessSet({ log_id: LOG, witness_threshold: 1, effective_from_tree_size: 1,
  witnesses: [{ public_key: Wx.publicKey }] }, root.privateKey, T0);
const tlAmb = s.buildWitnessTimeline([ws, wsAmb], root.publicKey);
ok(tlAmb.problems.some(p => /utkozes|ambiguous/.test(p)) && !tlAmb.timeline.some(e => e.from_tree_size === 1),
  'azonos effective_from ket keszlettel -> ambiguous, a hatar kihagyva (fail-closed)');

// ───────────────────────────────────────────────────────────────────────────
section('3. cosignature + core volatilitas (P2)');
// egy operator-alairt STH (mint a sidecar adja)
let sth = { axr_version: '0.3', record_type: 'sth', log_id: LOG, tree_size: 5,
  root_hash: 'sha256:' + 'a'.repeat(64), timestamp: T0(), previous_sth_hash: null };
sth.signature = axr.signReceipt(sth, op.privateKey);
const chainBefore = axr.chainHash(sth);
// witnessek cosignolnak (W1, W2)
const c1 = s.cosignWitness(sth, W1.privateKey);
const c2 = s.cosignWitness(sth, W2.privateKey);
sth = s.assembleWitnessCosignatures(sth, [c2, c1]); // forditva adva -> rendezni kell
ok(sth.witness_cosignatures[0].witness_fingerprint < sth.witness_cosignatures[1].witness_fingerprint,
  'a cosignature-ok fingerprint szerint rendezettek');
ok(axr.verifyReceipt(sth, op.publicKey), 'a cosignature-ok hozzaadasa NEM tori az operator-alairast (core P2)');
ok(axr.chainHash(sth) === chainBefore, 'a lanc-hash valtozatlan a cosignature-ok utan (core P2)');

// ───────────────────────────────────────────────────────────────────────────
section('4. verifyWitnessCosignatures');
const entry = s.witnessAt(tl.timeline, 5); // threshold 2, witnesses W1/W2/W3
const r = s.verifyWitnessCosignatures(sth, entry);
ok(r.validCount === 2 && r.threshold === 2 && r.anomalies.length === 0, '2 ervenyes cosignature, eleri a threshold-ot');
// threshold-alattisag: csak W1 cosignol -> validCount 1 < 2, DE nincs anomalia
let sthUnder = { ...sth }; delete sthUnder.witness_cosignatures;
sthUnder.signature = sth.signature;
sthUnder = s.assembleWitnessCosignatures(sthUnder, [s.cosignWitness(sthUnder, W1.privateKey)]);
const rUnder = s.verifyWitnessCosignatures(sthUnder, entry);
ok(rUnder.validCount === 1 && rUnder.anomalies.length === 0, 'threshold-alattisag NEM anomalia (validCount 1, under-witnessed)');
// nem-deklaralt witness (Wx)
let sthBad = { ...sth }; delete sthBad.witness_cosignatures; sthBad.signature = sth.signature;
sthBad = s.assembleWitnessCosignatures(sthBad, [s.cosignWitness(sthBad, W1.privateKey), s.cosignWitness(sthBad, Wx.privateKey)]);
ok(s.verifyWitnessCosignatures(sthBad, entry).anomalies.some(a => /nem-deklaralt/.test(a)),
  'nem-deklaralt witness cosignature -> anomalia');
// duplikalt witness
let sthDup = { ...sth }; delete sthDup.witness_cosignatures; sthDup.signature = sth.signature;
const cc = s.cosignWitness(sthDup, W1.privateKey);
sthDup.witness_cosignatures = [cc, cc];
ok(s.verifyWitnessCosignatures(sthDup, entry).anomalies.some(a => /sorrend|deklaralt/.test(a)) ||
   s.verifyWitnessCosignatures(sthDup, entry).validCount <= 1, 'duplikalt witness -> anomalia/nem szamit ketszer');
// hamisitott cosignature (rossz aláíras)
let sthForge = { ...sth }; delete sthForge.witness_cosignatures; sthForge.signature = sth.signature;
const forged = s.cosignWitness(sthForge, W1.privateKey); forged.signature = Buffer.from('hamis').toString('base64');
sthForge = s.assembleWitnessCosignatures(sthForge, [forged]);
ok(s.verifyWitnessCosignatures(sthForge, entry).anomalies.some(a => /ERVENYTELEN/.test(a)),
  'hamisitott cosignature-alairas -> anomalia');
// rendezetlen
let sthUnord = { ...sth };
sthUnord.witness_cosignatures = sth.witness_cosignatures.slice().reverse();
ok(s.verifyWitnessCosignatures(sthUnord, entry).anomalies.some(a => /sorrend/.test(a)),
  'rendezetlen cosignature-ok -> anomalia');

console.log(`\nOsszesen: ${pass} ok, ${fail} hiba`);
process.exit(fail ? 1 : 0);
