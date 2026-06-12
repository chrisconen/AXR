// ═══════════════════════════════════════════════════════════════════════════════
// AXR 0.5 - embedded_succession az anchor sidecar-ban (teszt)
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-anchor-succession-test.js
//
// Mit ellenoriz:
//   1. Backward-kompat: succession NELKUL az STH pontosan a mai (0.3) marad
//   2. Rotacio utan az utod kulcs ELSO STH-ja beagyazza a successiont
//      (embedded_succession), es a beagyazott rekord root-kulccsal verifikal
//   3. Az alairas ES a lanc fedi a beagyazast (manipulacio-evidens)
//   4. Idempotencia: a kovetkezo STH mar NEM agyazza be ujra
//   5. Red-team: rossz alairo kulcs / rossz role / hatar elotti alairas -> dob
//
// Nulla kulso fuggoseg.  Kilepesi kod: 0 ha minden zold, 1 ha barmi megbukik.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
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

// Fix idobelyeg a determinisztikussaghoz
const T0 = () => '2026-06-12T00:00:00.000Z';
const LOG = 'axr:anchor-succ-test:v1';

// Kulcsok: root (fuggetlen bizalmi horgony), A (genesis sth), B (utod), X (idegen)
const root = genKey(), A = genKey(), B = genKey(), X = genKey();
const fpA = s.keyFingerprint(A.publicKey);

// Minimalis level-receiptek - az anchor nem validalja a tartalmukat, csak hashel.
let leafSeq = 0;
function makeLeaves(n) {
  const out = [];
  for (let i = 0; i < n; i++) {
    leafSeq++;
    out.push({ axr_version: '0.3', receipt_type: 'step', receipt_id: 'leaf-' + leafSeq,
      timestamp: T0(), io: { input_hash: axr.sha256('in-' + leafSeq) } });
  }
  return out;
}
function appendLeaves(p, n) {
  fs.appendFileSync(p, makeLeaves(n).map(r => JSON.stringify(r)).join('\n') + '\n');
}
function readSths(p) {
  return fs.readFileSync(p, 'utf8').trim().split('\n').map(JSON.parse);
}

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-anchsucc-'));
  const receiptsPath = path.join(dir, 'receipts.jsonl');
  const sthPath = path.join(dir, 'sth.jsonl');
  fs.writeFileSync(receiptsPath, '');
  const base = { receiptsPath, sthPath, anchorsPath: path.join(dir, 'anchors.jsonl'),
    backends: ['local'], logId: LOG, now: T0 };

  // ─────────────────────────────────────────────────────────────────────────
  section('1. Backward-kompat: succession nelkul az STH a mai (0.3) marad');
  appendLeaves(receiptsPath, 3);
  await runAnchor({ ...base, privateKeyPem: A.privateKey });
  const sth1 = readSths(sthPath)[0];
  ok(sth1.axr_version === '0.3', 'succession nelkul axr_version 0.3');
  ok(!('embedded_succession' in sth1), 'succession nelkul nincs embedded_succession mezo');
  ok(axr.verifyReceipt(sth1, A.publicKey), 'a 0.3-as STH alairasa valtozatlanul verifikal');

  // ─────────────────────────────────────────────────────────────────────────
  section('2. Rotacio A -> B: az utod ELSO STH-ja beagyazza a successiont');
  const succAB = s.buildKeySuccession({
    log_id: LOG, role: 'sth', predecessor_fingerprint: fpA,
    successor_public_key: B.publicKey, effective_from_tree_size: 4, reason: 'scheduled'
  }, root.privateKey, T0);
  appendLeaves(receiptsPath, 2); // fa-meret 5 >= effective_from 4
  await runAnchor({ ...base, privateKeyPem: B.privateKey, succession: succAB });
  const sth2 = readSths(sthPath)[1];
  ok(sth2.axr_version === '0.5', 'beagyazo STH axr_version 0.5');
  ok(JSON.stringify(sth2.embedded_succession) === JSON.stringify(succAB),
    'embedded_succession = a teljes root-alairt rekord');
  ok(axr.verifyReceipt(sth2, B.publicKey), 'az STH-t az utod (B) irta ala, verifikal');
  ok(s.verifyKeySuccession(sth2.embedded_succession, root.publicKey).ok,
    'a beagyazott rekord a root-kulccsal verifikal');
  ok(sth2.previous_sth_hash === axr.chainHash(sth1), 'a lanc folytonos (sth1 -> sth2)');

  // ─────────────────────────────────────────────────────────────────────────
  section('3. Idempotencia: a kovetkezo STH mar nem agyaz be ujra');
  appendLeaves(receiptsPath, 1);
  await runAnchor({ ...base, privateKeyPem: B.privateKey, succession: succAB });
  const sth3 = readSths(sthPath)[2];
  ok(!('embedded_succession' in sth3), 'masodik futasnal nincs ujra-beagyazas');
  ok(sth3.axr_version === '0.3', 'a beagyazas utani STH visszaall 0.3-ra');
  ok(axr.verifyReceipt(sth3, B.publicKey), 'a kovetkezo STH is B-vel verifikal');

  // ─────────────────────────────────────────────────────────────────────────
  section('4. Red-team: a beagyazott rekord manipulacioja torik (alairas + lanc)');
  const tampered = JSON.parse(JSON.stringify(sth2));
  tampered.embedded_succession.reason = 'compromise-coverup';
  ok(!axr.verifyReceipt(tampered, B.publicKey),
    'manipulalt embedded_succession -> az STH alairasa ERVENYTELEN');
  ok(axr.chainHash(tampered) !== sth3.previous_sth_hash,
    'manipulalt embedded_succession -> a lanc-hash sem egyezik (sth3 nem ra mutat)');

  // ─────────────────────────────────────────────────────────────────────────
  section('5. Red-team: guard-ok dobnak');
  appendLeaves(receiptsPath, 1);
  // 5a. idegen kulcs (X) ir ala, de a succession B-t autorizalja
  let threw = false;
  try { await runAnchor({ ...base, privateKeyPem: X.privateKey, succession: succAB }); }
  catch (e) { threw = /successor_fingerprint/.test(e.message); }
  ok(threw, 'X alair B successionjevel -> fingerprint-guard dob');
  // 5b. role=receipt succession nem agyazhato STH-ba
  const succReceipt = s.buildKeySuccession({
    log_id: LOG, role: 'receipt', predecessor_fingerprint: fpA,
    successor_public_key: B.publicKey, effective_from_tree_size: 4
  }, root.privateKey, T0);
  threw = false;
  try { await runAnchor({ ...base, privateKeyPem: B.privateKey, succession: succReceipt }); }
  catch (e) { threw = /role=sth/.test(e.message); }
  ok(threw, 'role=receipt rekord -> role-guard dob');
  // 5c. hatar elotti alairas: effective_from a jelenlegi fa-meret folott
  const succFuture = s.buildKeySuccession({
    log_id: LOG, role: 'sth', predecessor_fingerprint: fpA,
    successor_public_key: B.publicKey, effective_from_tree_size: 1000
  }, root.privateKey, T0);
  threw = false;
  try { await runAnchor({ ...base, privateKeyPem: B.privateKey, succession: succFuture }); }
  catch (e) { threw = /effective_from_tree_size/.test(e.message); }
  ok(threw, 'fa-meret < effective_from -> hatar-guard dob (az utod meg nem irhat ala)');
  // 5d. idegen log ervenyes successionja nem agyazhato be (NEXUS-review talalata)
  const succOtherLog = s.buildKeySuccession({
    log_id: 'axr:masik-log:v1', role: 'sth', predecessor_fingerprint: fpA,
    successor_public_key: B.publicKey, effective_from_tree_size: 4
  }, root.privateKey, T0);
  threw = false;
  try { await runAnchor({ ...base, privateKeyPem: B.privateKey, succession: succOtherLog }); }
  catch (e) { threw = /log_id/.test(e.message); }
  ok(threw, 'masik log_id-ju rekord -> log-guard dob');
  // 5e. a guard-dobasok utan a lanc serulesmentes (nem keletkezett torz STH)
  ok(readSths(sthPath).length === 3, 'a sikertelen futasok nem irtak STH-t');

  // ─────────────────────────────────────────────────────────────────────────
  console.log(`\nOsszesen: ${pass} ok, ${fail} hiba`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('VARATLAN HIBA:', e); process.exit(1); });
