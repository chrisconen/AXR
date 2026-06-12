// ═══════════════════════════════════════════════════════════════════════════════
// AXR 0.5 - axr-key-succession.js CLI teszt
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-key-succession-cli-test.js
//
// Mit ellenoriz:
//   1. fingerprint parancs - byte-azonos a modul keyFingerprint-jevel
//   2. build (PEM predecessorral es kesz fingerprinttel) -> ervenyes, root-alairt
//      rekord, onellenorzessel
//   3. verify nyers root-pub.pem ellen es trust-root.json ellen (exit 0)
//   4. Red-team: hamisitott rekord / hamis root / hamisitott trust-root -> exit 1
//   5. Rossz hasznalat -> exit 2
//   6. End-to-end: a CLI-vel epitett rekordot a sidecar beagyazza (runAnchor)
//
// Nulla kulso fuggoseg.  Kilepesi kod: 0 zold, 1 hiba.
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

const CLI = path.join(__dirname, 'axr-key-succession.js');
function run(args) {
  try { return { code: 0, out: execFileSync('node', [CLI, ...args], { encoding: 'utf8', stdio: 'pipe' }) }; }
  catch (e) { return { code: e.status == null ? -1 : e.status, out: (e.stdout || '') + (e.stderr || '') }; }
}

const T0 = () => '2026-06-12T00:00:00.000Z';
const LOG = 'axr:cli-test:v1';
const root = genKey(), A = genKey(), B = genKey(), fakeRoot = genKey();

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-kscli-'));
const W = (name, content) => { const p = path.join(dir, name); fs.writeFileSync(p, content); return p; };
const rootPrivPath = W('root-priv.pem', root.privateKey);
const rootPubPath = W('root-pub.pem', root.publicKey);
const aPubPath = W('a-pub.pem', A.publicKey);
const bPubPath = W('b-pub.pem', B.publicKey);

// ───────────────────────────────────────────────────────────────────────────
section('1. fingerprint parancs');
const fpRes = run(['fingerprint', aPubPath]);
ok(fpRes.code === 0 && fpRes.out.trim() === s.keyFingerprint(A.publicKey),
  'a CLI fingerprint byte-azonos a modul keyFingerprint-jevel');

// ───────────────────────────────────────────────────────────────────────────
section('2. build: PEM predecessorral es kesz fingerprinttel');
const buildArgs = ['build', rootPrivPath, '--log-id', LOG, '--role', 'sth',
  '--successor', bPubPath, '--effective-from', '10', '--reason', 'scheduled'];
const b1 = run([...buildArgs, '--predecessor', aPubPath]);
ok(b1.code === 0, 'build PEM predecessorral: exit 0');
const rec1 = JSON.parse(b1.out);
ok(s.verifyKeySuccession(rec1, root.publicKey).ok, 'a rekord a root-kulccsal verifikal');
ok(rec1.predecessor_fingerprint === s.keyFingerprint(A.publicKey) &&
   rec1.successor_fingerprint === s.keyFingerprint(B.publicKey) &&
   rec1.effective_from_tree_size === 10 && rec1.role === 'sth' && rec1.log_id === LOG,
  'a rekord mezoi helyesek');
const b2 = run([...buildArgs, '--predecessor-fingerprint', s.keyFingerprint(A.publicKey)]);
ok(b2.code === 0 && JSON.parse(b2.out).predecessor_fingerprint === rec1.predecessor_fingerprint,
  'build kesz fingerprinttel: azonos predecessor');

// ───────────────────────────────────────────────────────────────────────────
section('3. verify: nyers root-pub es trust-root ellen');
const recPath = W('succession.json', JSON.stringify(rec1) + '\n');
ok(run(['verify', recPath, rootPubPath]).code === 0, 'verify root-pub.pem ellen: exit 0');
const tr = s.buildTrustRoot({ providers: [], logs: [{ log_id: LOG, genesis: { sth: A.publicKey, receipt: null } }] },
  root.privateKey, root.publicKey, T0);
const trPath = W('trust-root.json', JSON.stringify(tr) + '\n');
ok(run(['verify', recPath, trPath]).code === 0, 'verify trust-root.json ellen: exit 0');

// ───────────────────────────────────────────────────────────────────────────
section('4. Red-team');
const tampered = { ...rec1, effective_from_tree_size: 1 }; // a body valtozott, az alairas nem fedi
const tamperedPath = W('tampered.json', JSON.stringify(tampered) + '\n');
ok(run(['verify', tamperedPath, rootPubPath]).code === 1, 'hamisitott rekord -> exit 1');
const forged = s.buildKeySuccession({
  log_id: LOG, role: 'sth', predecessor_fingerprint: s.keyFingerprint(A.publicKey),
  successor_public_key: B.publicKey, effective_from_tree_size: 10
}, fakeRoot.privateKey, T0);
const forgedPath = W('forged.json', JSON.stringify(forged) + '\n');
ok(run(['verify', forgedPath, rootPubPath]).code === 1, 'hamis root-tal alairt rekord -> exit 1');
const badTr = JSON.parse(JSON.stringify(tr));
badTr.logs[0].genesis.sth = B.publicKey; // utolagos atiras, nincs ujra-alairas
const badTrPath = W('bad-trust-root.json', JSON.stringify(badTr) + '\n');
ok(run(['verify', recPath, badTrPath]).code === 1, 'hamisitott trust-root mint horgony -> exit 1 (fail-closed)');

// ───────────────────────────────────────────────────────────────────────────
section('5. Rossz hasznalat');
ok(run(['build', rootPrivPath, '--role', 'sth']).code === 2, 'hianyos build -> exit 2');
ok(run(['verify', recPath]).code === 2, 'hianyos verify -> exit 2');
ok(run(['nemletezik']).code === 2, 'ismeretlen parancs -> exit 2');

// ───────────────────────────────────────────────────────────────────────────
section('6. (0.6) revoke parancs');
const revRes = run(['revoke', rootPrivPath, '--log-id', LOG, '--role', 'receipt',
  '--revoked', aPubPath, '--revoked-at', '7', '--reason', 'compromise']);
ok(revRes.code === 0, 'revoke: exit 0');
const revRec = JSON.parse(revRes.out);
ok(s.verifyKeyRevocation(revRec, root.publicKey).ok && revRec.revoked_at_tree_size === 7,
  'a revokacio root-alairt es a mezok helyesek');
const revPath = W('revocation.json', JSON.stringify(revRec) + '\n');
ok(run(['verify', revPath, rootPubPath]).code === 0, 'verify felismeri es elfogadja a revokaciot');
const revTampered = W('rev-tampered.json', JSON.stringify({ ...revRec, revoked_at_tree_size: 1 }) + '\n');
ok(run(['verify', revTampered, rootPubPath]).code === 1, 'hamisitott revokacio -> exit 1');

// ───────────────────────────────────────────────────────────────────────────
section('7. (0.6) kvorum-ceremonia: body -> sign -> assemble');
const Q1 = genKey(), Q2 = genKey(), Q3 = genKey();
const qTr = s.buildQuorumTrustRoot({ providers: [], root_keys: [Q1.publicKey, Q2.publicKey, Q3.publicKey],
  threshold: 2, logs: [{ log_id: LOG, genesis: { sth: A.publicKey, receipt: null } }] },
  [Q1.privateKey, Q2.privateKey], T0);
const qTrPath = W('quorum-tr.json', JSON.stringify(qTr) + '\n');
const q1Priv = W('q1.pem', Q1.privateKey), q3Priv = W('q3.pem', Q3.privateKey);
// body
const bodyRes = run(['body', 'succession', '--log-id', LOG, '--role', 'sth',
  '--predecessor', aPubPath, '--successor', bPubPath, '--effective-from', '10']);
ok(bodyRes.code === 0 && !JSON.parse(bodyRes.out).signature, 'body: alairatlan torzs');
const bodyPath = W('body.json', bodyRes.out);
// sign x2 (kulon "gepeken")
const p1 = run(['sign', bodyPath, q1Priv]);
const p3 = run(['sign', bodyPath, q3Priv]);
ok(p1.code === 0 && p3.code === 0, 'sign: ket reszalairas keszult');
const p1Path = W('part1.json', p1.out), p3Path = W('part3.json', p3.out);
// assemble --verify: kvorum teljesul
const asm = run(['assemble', bodyPath, p1Path, p3Path, '--verify', qTrPath]);
ok(asm.code === 0, 'assemble --verify: exit 0 (2-of-3 teljesul)');
const asmRec = JSON.parse(asm.out);
ok(s.verifyKeySuccession(asmRec, qTr).ok, 'az osszefesult rekord a kvorum-roottal verifikal');
// assemble --verify kvorum alatt -> exit 1, nem ad ki hasznalhatatlan rekordot
const asmUnder = run(['assemble', bodyPath, p1Path, '--verify', qTrPath]);
ok(asmUnder.code === 1, 'assemble --verify kvorum alatt -> exit 1 (self-lockout vedelem)');
// sign mar alairt body-ra -> hiba
ok(run(['sign', W('signed-body.json', asm.out), q1Priv]).code === 2,
  'sign mar osszefesult rekordra -> exit 2');
// verify lanc-horgonnyal is megy (genesis -> utod lanc)
const S1 = genKey(), S2 = genKey(), S3 = genKey();
const succTr = s.buildTrustRootSuccessor({ providers: [], logs: [{ log_id: LOG, genesis: { sth: A.publicKey, receipt: null } }],
  root_keys: [S1.publicKey, S2.publicKey, S3.publicKey], threshold: 2 }, qTr, [Q1.privateKey, Q2.privateKey], T0);
const chainPath = W('chain.jsonl', JSON.stringify(qTr) + '\n' + JSON.stringify(succTr) + '\n');
const succByNew = s.buildQuorumKeySuccession({ log_id: LOG, role: 'sth',
  predecessor_fingerprint: s.keyFingerprint(A.publicKey), successor_public_key: B.publicKey,
  effective_from_tree_size: 10 }, [S1.privateKey, S2.privateKey], T0);
const succByNewPath = W('succ-by-new.json', JSON.stringify(succByNew) + '\n');
ok(run(['verify', succByNewPath, chainPath]).code === 0,
  'verify lanc-horgonnyal: az UJ kvorum rekordja az effektiv root ellen ervenyes');

// ───────────────────────────────────────────────────────────────────────────
section('8. End-to-end: a CLI-vel epitett rekordot a sidecar beagyazza');
(async () => {
  const logDir = path.join(dir, 'log'); fs.mkdirSync(logDir);
  const receiptsPath = path.join(logDir, 'receipts.jsonl');
  const mkLeaf = (i) => ({ axr_version: '0.3', receipt_type: 'step', receipt_id: 'leaf-' + i,
    timestamp: T0(), io: { input_hash: axr.sha256('in-' + i) } });
  const base = { receiptsPath, sthPath: path.join(logDir, 'sth.jsonl'),
    anchorsPath: path.join(logDir, 'anchors.jsonl'), backends: ['local'], logId: LOG, now: T0 };
  fs.writeFileSync(receiptsPath, Array.from({ length: 12 }, (_, i) => JSON.stringify(mkLeaf(i + 1))).join('\n') + '\n');
  await runAnchor({ ...base, privateKeyPem: B.privateKey, succession: rec1 }); // fa 12 >= effective_from 10
  const sth = JSON.parse(fs.readFileSync(base.sthPath, 'utf8').trim());
  ok(JSON.stringify(sth.embedded_succession) === JSON.stringify(rec1),
    'a CLI-vel epitett rekord valtozatlanul beagyazodott az utod elso STH-jaba');
  ok(axr.verifyReceipt(sth, B.publicKey), 'az STH az utod kulcsaval verifikal');

  console.log(`\nOsszesen: ${pass} ok, ${fail} hiba`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('VARATLAN HIBA:', e); process.exit(1); });
