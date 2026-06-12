// ═══════════════════════════════════════════════════════════════════════════════
// AXR 0.6 - kvorum-root (M-of-N multi-alairas) teszt
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-quorum-test.js
//
// Mit ellenoriz:
//   1. 2-of-3 kvorum trust root: epites, onverifikacio, modfelismeres
//   2. Kvorum-alairt succession: 2/3 ervenyes, idovonal-integracio
//   3. Red-team (Meridian-invariansok, MIND fail-closed):
//      M-1 alairas, duplikalt alairo, nem-deklaralt alairo, eltero body,
//      rendezetlen alairas-sorrend, utolagos 'signature' mezo, vegyes mod
//   4. Backward-kompat: a 0.5 egykulcsos ut valtozatlan; M=1/N=1 kvorum
//      ekvivalens viselkedesu; PEM-horgony tovabbra is mukodik
//
// Nulla kulso fuggoseg.  Kilepesi kod: 0 zold, 1 hiba.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const s = require('./axr-succession');

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

const T0 = () => '2026-06-12T12:00:00.000Z';
const LOG = 'axr:quorum-test:v1';

// Kvorum-tagok: R1, R2, R3 (deklaralt); X idegen. Operator: A (genesis), B (utod).
const R1 = genKey(), R2 = genKey(), R3 = genKey(), X = genKey();
const A = genKey(), B = genKey();
const ROOT_KEYS = [R1.publicKey, R2.publicKey, R3.publicKey];

// ───────────────────────────────────────────────────────────────────────────
section('1. 2-of-3 kvorum trust root');
const trOpts = { providers: [], root_keys: ROOT_KEYS, threshold: 2,
  logs: [{ log_id: LOG, genesis: { sth: A.publicKey, receipt: null } }] };
const tr = s.buildQuorumTrustRoot(trOpts, [R1.privateKey, R3.privateKey], T0);
ok(s.verifyTrustRoot(tr).ok, '2 alairoval epitett 2-of-3 trust root verifikal');
ok(s.trustRootMode(tr).mode === 'quorum', 'modfelismeres: quorum');
ok(Array.isArray(tr.signatures) && tr.signatures.length === 2 &&
   tr.signatures[0].key_fingerprint < tr.signatures[1].key_fingerprint,
  'a signatures fingerprint szerint rendezett (determinisztikus)');
const tr3 = s.buildQuorumTrustRoot(trOpts, [R1.privateKey, R2.privateKey, R3.privateKey], T0);
ok(s.verifyTrustRoot(tr3).ok, '3/3 alairas is ervenyes (threshold folott)');

// ───────────────────────────────────────────────────────────────────────────
section('2. Kvorum-alairt succession + idovonal');
const succOpts = { log_id: LOG, role: 'sth', predecessor_fingerprint: s.keyFingerprint(A.publicKey),
  successor_public_key: B.publicKey, effective_from_tree_size: 10, reason: 'scheduled' };
const succQ = s.buildQuorumKeySuccession(succOpts, [R2.privateKey, R3.privateKey], T0);
ok(s.verifyKeySuccession(succQ, tr).ok, 'kvorum-succession a trust-root horgonnyal verifikal');
const tl = s.buildKeyTimeline(A.publicKey, [succQ], 'sth', tr);
ok(tl.problems.length === 0 && tl.timeline.length === 2 && tl.timeline[1].authorized,
  'idovonal: a kvorum-autorizalt rotacio authorized');
ok(s.keyAtTreeSize(tl.timeline, 10).fingerprint === s.keyFingerprint(B.publicKey),
  'hatar-szabaly valtozatlan (tree_size 10 -> B)');

// ───────────────────────────────────────────────────────────────────────────
section('3. Red-team: minden anomalia fail-closed');
// 3a. M-1 alairas
const succ1 = s.buildQuorumKeySuccession(succOpts, [R1.privateKey], T0);
ok(!s.verifyKeySuccession(succ1, tr).ok, '1 alairas < threshold 2 -> elutasitva');
// 3b. duplikalt alairo: assemble dob; kezzel osszerakva a verify utasitja el
let threw = false;
const body = s.buildKeySuccessionBody(succOpts, T0);
const part1 = s.signQuorumPart(body, R1.privateKey);
try { s.assembleQuorum(body, [part1, part1]); } catch (e) { threw = /duplikalt/.test(e.message); }
ok(threw, 'assembleQuorum duplikalt alairora dob');
const dupRec = { ...body, signatures: [part1, part1] };
ok(!s.verifyKeySuccession(dupRec, tr).ok, 'kezzel gyartott duplikalt alairo -> elutasitva');
// 3c. nem-deklaralt alairo: 1 deklaralt + 1 idegen = kvorum NEM teljesul,
//     es az idegen jelenlet onmagaban is anomalia
const mixedRec = s.assembleQuorum(body, [part1, s.signQuorumPart(body, X.privateKey)]);
const mixedRes = s.verifyKeySuccession(mixedRec, tr);
ok(!mixedRes.ok && mixedRes.problems.some(p => /nem-deklaralt/.test(p)),
  'idegen alairo -> elutasitva, explicit jelzessel');
// 3d. eltero body: az alairasok mas tartalom folott keszultek
const tamperedQ = JSON.parse(JSON.stringify(succQ));
tamperedQ.effective_from_tree_size = 1;
ok(!s.verifyKeySuccession(tamperedQ, tr).ok, 'body-hamisitas a kvorum-alairasok utan -> elutasitva');
// 3e. rendezetlen alairas-sorrend (determinizmus-kenyszer)
const unordered = JSON.parse(JSON.stringify(succQ));
unordered.signatures = unordered.signatures.slice().reverse();
const unorderedRes = s.verifyKeySuccession(unordered, tr);
ok(!unorderedRes.ok && unorderedRes.problems.some(p => /sorrend/.test(p)),
  'rendezetlen signatures -> elutasitva (byte-determinizmus kenyszeritve)');
// 3f. utolagos legacy 'signature' mezo rabiggyesztese: a kvorum-alairt body
//     resze, tehat a hozzaadasa eltero body = torik
const extraSig = JSON.parse(JSON.stringify(succQ));
extraSig.signature = 'aGFtaXM=';
ok(!s.verifyKeySuccession(extraSig, tr).ok, 'utolagos signature mezo -> a kvorum-alairasok torik');
// 3g. vegyes modu trust root (root_public_key ES root_keys)
const mixedTr = JSON.parse(JSON.stringify(tr));
mixedTr.root_public_key = X.publicKey;
ok(!s.verifyTrustRoot(mixedTr).ok, 'vegyes modu trust root -> ervenytelen');
// 3h. tamadoi "kvorum": eleg idegen alairas, de egyik sem deklaralt
const attackerRec = s.assembleQuorum(body, [s.signQuorumPart(body, X.privateKey),
  s.signQuorumPart(body, genKey().privateKey)]);
ok(!s.verifyKeySuccession(attackerRec, tr).ok, '2 idegen alairas (sajat "kvorum") -> elutasitva');
// 3i. threshold-manipulacio a trust rootban (no re-sign) -> a trust root torik
const lowTr = JSON.parse(JSON.stringify(tr));
lowTr.threshold = 1;
ok(!s.verifyTrustRoot(lowTr).ok, 'threshold leszallitasa utolag -> a trust root alairasai torik');

// ───────────────────────────────────────────────────────────────────────────
section('4. Backward-kompat');
const single = genKey();
const trSingle = s.buildTrustRoot({ providers: [], logs: [{ log_id: LOG, genesis: { sth: A.publicKey, receipt: null } }] },
  single.privateKey, single.publicKey, T0);
ok(s.verifyTrustRoot(trSingle).ok, '0.5 egykulcsos trust root valtozatlanul verifikal');
ok(s.trustRootMode(trSingle).mode === 'single', 'modfelismeres: single');
const succLegacy = s.buildKeySuccession(succOpts, single.privateKey, T0);
ok(s.verifyKeySuccession(succLegacy, single.publicKey).ok, 'PEM-horgony (0.5 ut) valtozatlanul mukodik');
ok(s.verifyKeySuccession(succLegacy, trSingle).ok, 'egykulcsos trust-root objektum mint horgony is mukodik');
ok(!s.verifyKeySuccession(succLegacy, tr).ok, 'egykulcsos alairas a kvorum-root ellen -> elutasitva (nincs atjaras)');
// M=1/N=1 kvorum: ekvivalens szigorusagu, mas formaju
const tr11 = s.buildQuorumTrustRoot({ providers: [], root_keys: [single.publicKey], threshold: 1,
  logs: [{ log_id: LOG, genesis: { sth: A.publicKey, receipt: null } }] }, [single.privateKey], T0);
const succ11 = s.buildQuorumKeySuccession(succOpts, [single.privateKey], T0);
ok(s.verifyTrustRoot(tr11).ok && s.verifyKeySuccession(succ11, tr11).ok,
  'M=1/N=1 kvorum mukodik (a legacy formaval parhuzamos ut)');

console.log(`\nOsszesen: ${pass} ok, ${fail} hiba`);
process.exit(fail ? 1 : 0);
