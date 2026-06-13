// ═══════════════════════════════════════════════════════════════════════════════
// AXR 0.8 - axr-witness CLI teszt (stateful sign + verify)
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-witness-cli-test.js
//
// Mit ellenoriz:
//   1. sign: cosignol egy STH-t, a state frissul, a cosignature verifikal
//   2. STATEFUL elutasitas (a preventiv invarians):
//      - kisebb tree_size (TRUNCATION) -> exit 1
//      - azonos tree_size + eltero root (EQUIVOCATION) -> exit 1
//      - azonos tree_size + azonos root (idempotens) -> exit 0
//      - nagyobb tree_size (append-only) -> exit 0, state elorelep
//   3. verify: threshold teljesul -> exit 0; under-witnessed -> exit 1;
//      anomalia (nem-deklaralt witness) -> exit 1
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

let pass = 0, fail = 0;
function ok(cond, name) { if (cond) { pass++; } else { fail++; console.log('  FAIL: ' + name); } }
function section(t) { console.log('\n' + t); }

function genKey() {
  const kp = crypto.generateKeyPairSync('ed25519');
  return { privateKey: kp.privateKey.export({ type: 'pkcs8', format: 'pem' }),
           publicKey: kp.publicKey.export({ type: 'spki', format: 'pem' }) };
}
const T0 = () => '2026-06-13T11:00:00.000Z';
const LOG = 'axr:witness-cli:v1';
const root = genKey(), op = genKey(), W1 = genKey(), W2 = genKey(), Wx = genKey();
const CLI = path.join(__dirname, 'axr-witness.js');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-wcli-'));
const W = (n, c) => { const p = path.join(dir, n); fs.writeFileSync(p, c); return p; };
const w1Priv = W('w1.pem', W1.privateKey);

function mkSth(tree_size, rootTag) {
  const sth = { axr_version: '0.3', record_type: 'sth', log_id: LOG, tree_size,
    root_hash: 'sha256:' + crypto.createHash('sha256').update(rootTag || ('r' + tree_size)).digest('hex'),
    timestamp: T0(), previous_sth_hash: null };
  sth.signature = axr.signReceipt(sth, op.privateKey);
  return sth;
}
function run(args, env) {
  try { return { code: 0, out: execFileSync('node', [CLI, ...args], { encoding: 'utf8', stdio: 'pipe',
    env: env ? Object.assign({}, process.env, env) : process.env }) }; }
  catch (e) { return { code: e.status == null ? -1 : e.status, out: (e.stdout || '') + (e.stderr || '') }; }
}

// ───────────────────────────────────────────────────────────────────────────
section('1. sign: alap cosignolas');
const sth5 = W('sth5.json', JSON.stringify(mkSth(5)) + '\n');
const state = path.join(dir, 'w1-state.json');
const r1 = run(['sign', sth5, w1Priv, '--state', state]);
ok(r1.code === 0, 'sign exit 0');
const cosig = JSON.parse(r1.out);
ok(cosig.witness_fingerprint === s.keyFingerprint(W1.publicKey) && cosig.signature, 'a cosignature a witness kulcsahoz tartozik');
ok(fs.existsSync(state) && JSON.parse(fs.readFileSync(state, 'utf8'))[LOG].tree_size === 5, 'a state frissult (tree_size 5)');

// ───────────────────────────────────────────────────────────────────────────
section('2. STATEFUL elutasitas');
// kisebb tree_size -> TRUNCATION
const sth3 = W('sth3.json', JSON.stringify(mkSth(3)) + '\n');
const rTrunc = run(['sign', sth3, w1Priv, '--state', state]);
ok(rTrunc.code === 1 && /TRUNCATION/.test(rTrunc.out), 'kisebb tree_size -> elutasitva (TRUNCATION)');
// azonos tree_size, eltero root -> EQUIVOCATION
const sth5b = W('sth5b.json', JSON.stringify(mkSth(5, 'MASIK-FA')) + '\n');
const rEq = run(['sign', sth5b, w1Priv, '--state', state]);
ok(rEq.code === 1 && /EQUIVOCATION/.test(rEq.out), 'azonos tree_size + eltero root -> elutasitva (EQUIVOCATION)');
// azonos tree_size, azonos root -> idempotens
const rIdem = run(['sign', sth5, w1Priv, '--state', state]);
ok(rIdem.code === 0, 'azonos tree_size + azonos root -> idempotens, exit 0');
// nagyobb tree_size -> append-only ok
const sth8 = W('sth8.json', JSON.stringify(mkSth(8)) + '\n');
const rExt = run(['sign', sth8, w1Priv, '--state', state]);
ok(rExt.code === 0 && JSON.parse(fs.readFileSync(state, 'utf8'))[LOG].tree_size === 8,
  'nagyobb tree_size -> elfogadva, a state elorelep (8)');

// ───────────────────────────────────────────────────────────────────────────
section('2b. state-iras fallback (nem-atomi mod: sandbox/halozati FS)');
// AXR_WITNESS_NO_ATOMIC: a rename helyett kozvetlen iras - a cosignature
// kibocsatasat es a state-frissitest egy rename-tilto FS sem blokkolhatja.
const naState = path.join(dir, 'w1-noatomic-state.json');
const sthNA = W('sthNA.json', JSON.stringify(mkSth(5)) + '\n');
const rNA = run(['sign', sthNA, w1Priv, '--state', naState], { AXR_WITNESS_NO_ATOMIC: '1' });
ok(rNA.code === 0, 'nem-atomi mod: sign exit 0');
const cosigNA = JSON.parse(rNA.out);
ok(cosigNA.witness_fingerprint === s.keyFingerprint(W1.publicKey) && cosigNA.signature,
  'nem-atomi mod: a cosignature helyes (a determinisztikus alairas attol meg azonos)');
ok(fs.existsSync(naState) && JSON.parse(fs.readFileSync(naState, 'utf8'))[LOG].tree_size === 5,
  'nem-atomi mod: a state frissult (tree_size 5), .tmp nem maradt');
ok(!fs.existsSync(naState + '.tmp'), 'nem-atomi mod: nincs hatrahagyott .tmp');
// a stateful invarians a fallback uton is el: kisebb tree_size elutasitva
const rNATrunc = run(['sign', sth3, w1Priv, '--state', naState], { AXR_WITNESS_NO_ATOMIC: '1' });
ok(rNATrunc.code === 1 && /TRUNCATION/.test(rNATrunc.out),
  'nem-atomi mod: a stateful TRUNCATION-vedelem tovabbra is el');

// ───────────────────────────────────────────────────────────────────────────
section('3. verify');
// witness_set: W1, W2, threshold 2
const trustRoot = s.buildTrustRoot({ providers: [],
  logs: [{ log_id: LOG, genesis: { sth: op.publicKey, receipt: op.publicKey } }] },
  root.privateKey, root.publicKey, T0);
const wsObj = s.buildWitnessSet({ log_id: LOG, witness_threshold: 2, effective_from_tree_size: 1,
  witnesses: [{ name: 'w1', public_key: W1.publicKey }, { name: 'w2', public_key: W2.publicKey }] },
  root.privateKey, T0);
const wsPath = W('witness-set.json', JSON.stringify(wsObj) + '\n');
const rootPubPath = W('root-pub.pem', root.publicKey);
// egy STH ket cosignature-rel (W1 + W2)
let sthC = mkSth(10);
sthC = s.assembleWitnessCosignatures(sthC, [s.cosignWitness(sthC, W1.privateKey), s.cosignWitness(sthC, W2.privateKey)]);
const sthCPath = W('sth-cosig.json', JSON.stringify(sthC) + '\n');
ok(run(['verify', sthCPath, wsPath, rootPubPath]).code === 0, 'verify: 2/2 cosignature, threshold teljesul -> exit 0');
// under-witnessed: csak W1
let sthU = mkSth(11);
sthU = s.assembleWitnessCosignatures(sthU, [s.cosignWitness(sthU, W1.privateKey)]);
const sthUPath = W('sth-under.json', JSON.stringify(sthU) + '\n');
const rU = run(['verify', sthUPath, wsPath, rootPubPath]);
ok(rU.code === 1 && /UNDER_WITNESSED/.test(rU.out), 'verify: 1/2 -> UNDER_WITNESSED, exit 1');
// anomalia: nem-deklaralt witness (Wx)
let sthA = mkSth(12);
sthA = s.assembleWitnessCosignatures(sthA, [s.cosignWitness(sthA, W1.privateKey), s.cosignWitness(sthA, Wx.privateKey)]);
const sthAPath = W('sth-anom.json', JSON.stringify(sthA) + '\n');
const rA = run(['verify', sthAPath, wsPath, rootPubPath]);
ok(rA.code === 1 && /anomalia|ERVENYTELEN/.test(rA.out), 'verify: nem-deklaralt witness -> anomalia, exit 1');

console.log(`\nOsszesen: ${pass} ok, ${fail} hiba`);
process.exit(fail ? 1 : 0);
