// AXR 0.5 key-succession teszt - a tervezesi red-team eseteit ellenorzi.
const crypto = require('crypto');
const s = require('./axr-succession');

let pass = 0, fail = 0;
function ok(cond, name) { if (cond) { pass++; } else { fail++; console.log('  FAIL: ' + name); } }
function section(t) { console.log('\n' + t); }

function genKey() {
  return crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
}

// Fix idobelyeg a determinisztikussaghoz
const T0 = () => '2026-01-01T00:00:00.000Z';

// Kulcsok: root (fuggetlen), A (genesis sth), B (utod), C (masodik utod),
// X (jogosulatlan), R (genesis receipt)
const root = genKey();
const A = genKey(), B = genKey(), C = genKey(), X = genKey(), R = genKey();
const LOG = 'axr:test:v1';

const fpA = s.keyFingerprint(A.publicKey);
const fpB = s.keyFingerprint(B.publicKey);
const fpC = s.keyFingerprint(C.publicKey);

// Egy STH-szeru osztalyozo, ahogy a monitor hasznalja majd:
// adott tree_size-nal melyik kulcs az ervenyes, es autorizalt-e.
function classify(timeline, treeSize, signingFp) {
  const e = s.keyAtTreeSize(timeline, treeSize);
  if (!e) return 'NO_KEY';                         // degradalt / fail-closed
  if (e.fingerprint !== signingFp) return 'KEY_MISMATCH';
  return e.authorized ? 'AUTHORIZED' : 'UNAUTHORIZED';
}

// ───────────────────────────────────────────────────────────────────────────
section('1. Genesis trust-root + autorizalt rotacio (A -> B @ tree_size 10)');
const tr = s.buildTrustRoot({
  providers: [],
  logs: [{ log_id: LOG, genesis: { sth: A.publicKey, receipt: R.publicKey } } ]
}, root.privateKey, root.publicKey, T0);
ok(s.verifyTrustRoot(tr).ok, 'trust-root verifikal');
ok(s.genesisKey(tr, LOG, 'sth') === A.publicKey, 'genesis sth = A');
ok(s.genesisKey(tr, LOG, 'receipt') === R.publicKey, 'genesis receipt = R');

const succAB = s.buildKeySuccession({
  log_id: LOG, role: 'sth', predecessor_fingerprint: fpA,
  successor_public_key: B.publicKey, effective_from_tree_size: 10, reason: 'scheduled'
}, root.privateKey, T0);
ok(s.verifyKeySuccession(succAB, root.publicKey).ok, 'succession A->B verifikal a root-kulccsal');

const tl1 = s.buildKeyTimeline(s.genesisKey(tr, LOG, 'sth'), [succAB], 'sth', root.publicKey);
ok(tl1.problems.length === 0, 'tiszta idovonal, nincs problema');
ok(tl1.timeline.length === 2, 'ket szegmens (genesis + B)');

// hatar-szabaly (off-by-one): tree_size 9 meg A, tree_size 10 mar B
ok(classify(tl1.timeline, 9, fpA) === 'AUTHORIZED', 'tree_size 9 -> A autorizalt');
ok(classify(tl1.timeline, 10, fpB) === 'AUTHORIZED', 'tree_size 10 -> B autorizalt (hatar)');
ok(classify(tl1.timeline, 50, fpB) === 'AUTHORIZED', 'tree_size 50 -> B autorizalt');
// regi kulcs az uj korszakban / uj kulcs a regi korszakban -> mismatch
ok(classify(tl1.timeline, 10, fpA) === 'KEY_MISMATCH', 'tree_size 10 A-val -> mismatch');
ok(classify(tl1.timeline, 9, fpB) === 'KEY_MISMATCH', 'tree_size 9 B-vel -> mismatch');

// ───────────────────────────────────────────────────────────────────────────
section('2. Jogosulatlan csere (X aláír, de nincs succession)');
const tl2 = s.buildKeyTimeline(A.publicKey, [succAB], 'sth', root.publicKey);
ok(classify(tl2.timeline, 20, s.keyFingerprint(X.publicKey)) === 'KEY_MISMATCH',
  'X ismeretlen kulcs -> mismatch (a monitor ezt KEY_CHANGED_UNAUTHORIZED-kent kezeli)');

// ───────────────────────────────────────────────────────────────────────────
section('3. Hianyzo root-genesis -> degradalt / fail-closed');
const tl3 = s.buildKeyTimeline(null, [succAB], 'sth', root.publicKey);
ok(tl3.timeline.length === 0, 'ures idovonal genesis nelkul');
ok(tl3.problems.length > 0, 'jelzi a degradalt modot');
ok(classify(tl3.timeline, 10, fpB) === 'NO_KEY', 'NO_KEY -> a monitor fail-closed kritikus');

// ───────────────────────────────────────────────────────────────────────────
section('4. Lanc A -> B -> C, majd out-of-order / utkozes');
const succBC = s.buildKeySuccession({
  log_id: LOG, role: 'sth', predecessor_fingerprint: fpB,
  successor_public_key: C.publicKey, effective_from_tree_size: 30, reason: 'scheduled'
}, root.privateKey, T0);
const tl4 = s.buildKeyTimeline(A.publicKey, [succAB, succBC], 'sth', root.publicKey);
ok(tl4.problems.length === 0, 'A->B->C tiszta lanc');
ok(classify(tl4.timeline, 35, fpC) === 'AUTHORIZED', 'tree_size 35 -> C autorizalt');
ok(classify(tl4.timeline, 25, fpB) === 'AUTHORIZED', 'tree_size 25 -> B autorizalt');

// utkozes: ket succession ugyanarra az effective_from-ra
const succAB2 = s.buildKeySuccession({
  log_id: LOG, role: 'sth', predecessor_fingerprint: fpA,
  successor_public_key: C.publicKey, effective_from_tree_size: 10, reason: 'split'
}, root.privateKey, T0);
const tl4b = s.buildKeyTimeline(A.publicKey, [succAB, succAB2], 'sth', root.publicKey);
ok(tl4b.problems.some(p => /utkozes|sorrend/.test(p)), 'ket succession azonos effective_from -> utkozes jelzes');

// FORK fail-closed (Meridian-review talalata: first-wins kiskapu): konkurens
// successionoknel EGYIK ag sem autorizalt, es a fork utani "szabalyos"
// folytatas sem - kulonben eltero lathatosagu monitorok mas-mas aktiv kulcsot
// fogadnanak el ugyanarra a tree_size-ra.
ok(classify(tl4b.timeline, 15, fpB) !== 'AUTHORIZED', 'fork: a B ag NEM autorizalt');
ok(classify(tl4b.timeline, 15, fpC) !== 'AUTHORIZED', 'fork: a C ag SEM autorizalt');
const succBX = s.buildKeySuccession({
  log_id: LOG, role: 'sth', predecessor_fingerprint: fpB,
  successor_public_key: X.publicKey, effective_from_tree_size: 20, reason: 'post-fork'
}, root.privateKey, T0);
const tl4c = s.buildKeyTimeline(A.publicKey, [succAB, succAB2, succBX], 'sth', root.publicKey);
ok(classify(tl4c.timeline, 25, s.keyFingerprint(X.publicKey)) !== 'AUTHORIZED',
  'a fork egyik agara epitett tovabbi rotacio sem autorizalt (lanc-merges)');

// ───────────────────────────────────────────────────────────────────────────
section('5. Tort lanc / hezag (A->B megvan, de C->D-t adunk B->C nelkul)');
const D = genKey();
const succCD = s.buildKeySuccession({
  log_id: LOG, role: 'sth', predecessor_fingerprint: fpC,  // C-rol, de C nem aktiv (B az)
  successor_public_key: D.publicKey, effective_from_tree_size: 30, reason: 'scheduled'
}, root.privateKey, T0);
const tl5 = s.buildKeyTimeline(A.publicKey, [succAB, succCD], 'sth', root.publicKey);
ok(tl5.problems.some(p => /tort lanc/.test(p)), 'tort lanc jelzes (predecessor != aktiv)');
const seg = tl5.timeline.find(e => e.fingerprint === s.keyFingerprint(D.publicKey));
ok(seg && seg.authorized === false, 'a D szegmens authorized=false');
ok(classify(tl5.timeline, 35, s.keyFingerprint(D.publicKey)) === 'UNAUTHORIZED',
  'tree_size 35 D-vel -> UNAUTHORIZED');

// tranzitiv autorizacio: a tort szem UTAN szabalyosan lancolt utod sem gyogyul
// vissza - kulonben a tamado egy tort ugrassal beallna, es a ra epitett tovabbi
// rotacioi mar autorizaltnak latszananak (NEXUS-review talalata)
const E = genKey();
const succDE = s.buildKeySuccession({
  log_id: LOG, role: 'sth', predecessor_fingerprint: s.keyFingerprint(D.publicKey),
  successor_public_key: E.publicKey, effective_from_tree_size: 40, reason: 'scheduled'
}, root.privateKey, T0);
const tl5b = s.buildKeyTimeline(A.publicKey, [succAB, succCD, succDE], 'sth', root.publicKey);
ok(classify(tl5b.timeline, 45, s.keyFingerprint(E.publicKey)) === 'UNAUTHORIZED',
  'a tort szemre szabalyosan lancolt E sem autorizalt (nincs "ongyogyulas")');

// ───────────────────────────────────────────────────────────────────────────
section('6. Role-konfuzio: receipt-role succession NEM mozdithatja az sth idovonalat');
const succReceipt = s.buildKeySuccession({
  log_id: LOG, role: 'receipt', predecessor_fingerprint: s.keyFingerprint(R.publicKey),
  successor_public_key: B.publicKey, effective_from_tree_size: 5, reason: 'scheduled'
}, root.privateKey, T0);
const tl6 = s.buildKeyTimeline(A.publicKey, [succReceipt], 'sth', root.publicKey);
ok(tl6.timeline.length === 1, 'sth idovonal valtozatlan (csak genesis), receipt-succession kiszurve');
ok(classify(tl6.timeline, 10, fpA) === 'AUTHORIZED', 'tree_size 10 -> meg mindig A');

// ───────────────────────────────────────────────────────────────────────────
section('7. Hamisitott succession (alairas serult) -> elvetes');
const tampered = JSON.parse(JSON.stringify(succAB));
tampered.effective_from_tree_size = 1;  // a body megvaltozott, az alairas nem fedi
ok(!s.verifyKeySuccession(tampered, root.publicKey).ok, 'hamisitott succession nem verifikal');
const tl7 = s.buildKeyTimeline(A.publicKey, [tampered], 'sth', root.publicKey);
ok(tl7.timeline.length === 1, 'hamisitott succession kimaradt az idovonalbol');
ok(tl7.problems.some(p => /elvetett/.test(p)), 'jelzi az elvetett successiont');

// ───────────────────────────────────────────────────────────────────────────
section('8. successor_fingerprint nem egyezik a kulccsal -> elvetes');
// A body-t ervenyesen alairjuk, de a deklaralt fingerprint hazudik (fpC, holott a
// kulcs B). Az alairas atmegy; a fingerprint-konzisztencia-ellenorzesnek kell elkapnia.
const canonicalize = require('./axr-core').canonicalize;
const fpForged = JSON.parse(JSON.stringify(succAB));
fpForged.successor_fingerprint = fpC;  // a successor_public_key tovabbra is B
delete fpForged.signature;
fpForged.signature = crypto.sign(null, Buffer.from(canonicalize(fpForged), 'utf8'),
  crypto.createPrivateKey(root.privateKey)).toString('base64');
const v8 = s.verifyKeySuccession(fpForged, root.publicKey);
ok(!v8.ok, 'fingerprint-mismatch elbukik az ellenorzesen');
ok(v8.problems.some(p => /successor_fingerprint nem egyezik/.test(p)), 'a konkret ok: fingerprint-mismatch');

// ───────────────────────────────────────────────────────────────────────────
section('9. Rossz root-kulccsal alairt succession -> elvetes');
const evil = genKey();
const succEvil = s.buildKeySuccession({
  log_id: LOG, role: 'sth', predecessor_fingerprint: fpA,
  successor_public_key: X.publicKey, effective_from_tree_size: 10, reason: 'attack'
}, evil.privateKey, T0);  // NEM a valodi root irta ala
ok(!s.verifyKeySuccession(succEvil, root.publicKey).ok, 'idegen root-kulccsal alairt succession nem verifikal');
const tl9 = s.buildKeyTimeline(A.publicKey, [succEvil], 'sth', root.publicKey);
ok(classify(tl9.timeline, 10, s.keyFingerprint(X.publicKey)) === 'KEY_MISMATCH',
  'a tamado kulcsa nem kerul be -> mismatch (UNAUTHORIZED)');

// ───────────────────────────────────────────────────────────────────────────
console.log('\n' + '─'.repeat(60));
console.log('PASS: ' + pass + '  FAIL: ' + fail);
process.exit(fail ? 1 : 0);
