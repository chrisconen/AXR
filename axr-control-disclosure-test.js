// ═══════════════════════════════════════════════════════════════════════════════
// AXR 1.5 - Reszleges control-disclosure (egyetlen governance-rekord inclusion proof)
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-control-disclosure-test.js   (Python eset kihagyva, ha nincs)
//
// Mit ellenoriz:
//   1. A disclosure control_root_hash-a EGYEZIK a valos, anchorolt STH
//      commitmentjevel (a buildControlDisclosure es a sidecar ugyanazt a Merkle-
//      gyokeret szamolja)
//   2. Minden indexre: buildControlDisclosure -> verifyControlDisclosure OK az STH
//      gyokerere; ADATVEDELEM: a disclosure CSAK egy rekordot tartalmaz
//   3. Tamper a rekordon / rossz index / rossz vart gyoker -> elutasitas
//   4. CLI e2e: 'control prove' + 'control verify-inclusion' (--key + --trust-root)
//      -> exit 0; tamperelt disclosure -> exit 1
//   5. Cross-impl: a Python verify_control_disclosure ugyanazt mondja (parity)
//
// Nulla kulso fuggoseg.  Kilepesi kod: 0 zold, 1 hiba.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const core = require('./axr-core');
const s = require('./axr-succession');
const control = require('./axr-control');
const { runAnchor } = require('./axr-anchor');

let pass = 0, fail = 0;
function ok(cond, name) { if (cond) { pass++; } else { fail++; console.log('  FAIL: ' + name); } }
function section(t) { console.log('\n' + t); }
function genKey() {
  const kp = crypto.generateKeyPairSync('ed25519');
  return { privateKey: kp.privateKey.export({ type: 'pkcs8', format: 'pem' }),
           publicKey: kp.publicKey.export({ type: 'spki', format: 'pem' }) };
}
function findPython() {
  for (const cand of ['python3', 'python']) {
    try { const v = execFileSync(cand, ['--version'], { encoding: 'utf8', stdio: 'pipe' });
      if (/^Python 3\./.test(v.trim())) return cand; } catch (e) {}
  }
  return null;
}
const PYTHON = findPython();
const CLI = path.join(__dirname, 'axr-key-succession.js');

const T0 = () => '2026-06-13T16:00:00.000Z';
const LOG = 'axr:control-disclosure:v1';
const root = genKey(), op = genKey(), W1 = genKey(), W2 = genKey();

const trustRoot = s.buildTrustRoot({ providers: [],
  logs: [{ log_id: LOG, genesis: { sth: op.publicKey, receipt: op.publicKey } }] },
  root.privateKey, root.publicKey, T0);
// 3 governance-rekord a control logba
const witnessSet = s.buildWitnessSet({ log_id: LOG, witness_threshold: 2, effective_from_tree_size: 1,
  witnesses: [{ name: 'a', public_key: W1.publicKey }, { name: 'b', public_key: W2.publicKey }] }, root.privateKey, T0);
const rev = s.buildWitnessRevocation({ log_id: LOG, revoked_fingerprint: s.keyFingerprint(W2.publicKey), revoked_at_tree_size: 10 }, root.privateKey);
const sus = s.buildWitnessSuspension({ log_id: LOG, suspended_fingerprint: s.keyFingerprint(W1.publicKey), suspended_from_tree_size: 4, suspended_until_tree_size: 8 }, root.privateKey);
const CONTROL = [witnessSet, rev, sus];

function sign(obj) { const r = { ...obj }; delete r.signature; r.signature = core.signReceipt(r, op.privateKey); return r; }

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-cdisc-'));
  const receiptsPath = path.join(dir, 'receipts.jsonl');
  const sthPath = path.join(dir, 'sth.jsonl');
  const controlPath = path.join(dir, 'control.jsonl');
  const trPath = path.join(dir, 'trust-root.json');
  const keyPath = path.join(dir, 'op.pem');
  fs.writeFileSync(trPath, JSON.stringify(trustRoot) + '\n');
  fs.writeFileSync(controlPath, CONTROL.map(r => JSON.stringify(r)).join('\n') + '\n');
  fs.writeFileSync(keyPath, op.publicKey);
  // egy alairt leaf-receipt, hogy legyen mit horgonyozni
  const rc = sign({ axr_version: '0.3', receipt_type: 'step', receipt_id: 'r1', timestamp: T0(),
    step: { node_name: 'n', node_type: 't', kind: 'deterministic', deterministic: true, model: null },
    io: { input_hash: core.sha256('x'), output_hash: null, input_summary: {}, decision: null },
    inputs: [], approval: null, previous_receipt_hash: null, anchor_ref: null });
  fs.writeFileSync(receiptsPath, JSON.stringify(rc) + '\n');
  await runAnchor({ receiptsPath, sthPath, anchorsPath: path.join(dir, 'anchors.jsonl'),
    backends: ['local'], logId: LOG, now: T0, privateKeyPem: op.privateKey,
    controlPath, controlTrustRootPath: trPath });
  const sth = fs.readFileSync(sthPath, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse).find(r => r.record_type === 'sth');

  // ───────────────────────────────────────────────────────────────────────────
  section('1. A disclosure gyokere egyezik az anchorolt STH commitmentjevel');
  ok(sth && typeof sth.control_root_hash === 'string' && sth.control_size === 3,
    'az STH commitol a 3 control-rekordra (control_size=3)');
  ok(control.controlRoot(CONTROL) === sth.control_root_hash, 'controlRoot(CONTROL) === STH.control_root_hash');

  // ───────────────────────────────────────────────────────────────────────────
  section('2. Minden index: build -> verify az STH gyokerere + adatvedelem');
  for (let i = 0; i < CONTROL.length; i++) {
    const disc = control.buildControlDisclosure(CONTROL, i);
    ok(disc.control_root_hash === sth.control_root_hash && disc.leaf_index === i && disc.control_size === 3,
      `[idx ${i}] disclosure gyokere == STH, leaf_index/control_size helyes`);
    ok(control.verifyControlDisclosure(disc, sth.control_root_hash).ok,
      `[idx ${i}] verifyControlDisclosure OK az STH gyokerere`);
    // ADATVEDELEM: csak EGY rekord van a disclosure-ben (a tobbi nincs felfedve)
    ok(disc.record.record_type === CONTROL[i].record_type && !Array.isArray(disc.record),
      `[idx ${i}] a disclosure CSAK az adott rekordot tartalmazza (a tobbit nem)`);
  }

  // ───────────────────────────────────────────────────────────────────────────
  section('3. Tamper / rossz index / rossz vart gyoker -> elutasitas');
  const d1 = control.buildControlDisclosure(CONTROL, 1);
  const tampered = JSON.parse(JSON.stringify(d1));
  tampered.record.revoked_at_tree_size = 999;   // a rekord megvaltoztatva -> mas leaf-hash
  ok(!control.verifyControlDisclosure(tampered, sth.control_root_hash).ok, 'tamperelt rekord -> inclusion NEM verifikal');
  const wrongIdx = JSON.parse(JSON.stringify(d1)); wrongIdx.leaf_index = 0;
  ok(!control.verifyControlDisclosure(wrongIdx, sth.control_root_hash).ok, 'rossz leaf_index -> NEM verifikal');
  ok(!control.verifyControlDisclosure(d1, 'sha256:' + '0'.repeat(64)).ok, 'rossz vart gyoker -> NEM verifikal (commitment-eltérés)');
  let threw = false;
  try { control.buildControlDisclosure(CONTROL, 9); } catch (e) { threw = true; }
  ok(threw, 'tartomanyon kivuli index -> build dobas');

  // ───────────────────────────────────────────────────────────────────────────
  section('4. CLI e2e: control prove + verify-inclusion');
  function cli(args) {
    try { return { code: 0, out: execFileSync('node', [CLI, ...args], { encoding: 'utf8', stdio: 'pipe' }) }; }
    catch (e) { return { code: e.status == null ? -1 : e.status, out: (e.stdout || '') + (e.stderr || '') }; }
  }
  const discPath = path.join(dir, 'disc.json');
  const rProve = cli(['control', 'prove', controlPath, '1', '--out', discPath]);
  ok(rProve.code === 0 && fs.existsSync(discPath), 'control prove: exit 0, disclosure kiirva');
  const rVer = cli(['control', 'verify-inclusion', discPath, sthPath, '--key', keyPath, '--trust-root', trPath]);
  ok(rVer.code === 0 && /ERVENYES/.test(rVer.out), 'control verify-inclusion (--key + --trust-root): exit 0 ERVENYES');
  // tamperelt disclosure -> exit 1
  const badPath = path.join(dir, 'bad.json');
  const bad = JSON.parse(fs.readFileSync(discPath, 'utf8')); bad.record.revoked_at_tree_size = 777;
  fs.writeFileSync(badPath, JSON.stringify(bad) + '\n');
  ok(cli(['control', 'verify-inclusion', badPath, sthPath, '--key', keyPath]).code === 1, 'tamperelt disclosure -> exit 1');
  // NEXUS-review: a --key (STH-alairas) KOTELEZO - nelkule a commitment hiteltelen
  ok(cli(['control', 'verify-inclusion', discPath, sthPath]).code === 2, '--key nelkul -> exit 2 (kotelezo: az STH-alairas a bizalmi horgony)');
  // NEXUS-review: log_id-szuures - ha a disclosure rekordja mas loghoz tartozik,
  // nincs egyezo STH (a control_root_hash veletlen egyezese sem eleg)
  const xLog = JSON.parse(fs.readFileSync(discPath, 'utf8')); xLog.record = { ...xLog.record, log_id: 'axr:OTHER:v1' };
  const xPath = path.join(dir, 'xlog.json'); fs.writeFileSync(xPath, JSON.stringify(xLog) + '\n');
  ok(cli(['control', 'verify-inclusion', xPath, sthPath, '--key', keyPath]).code === 1, 'idegen log_id-ju rekord -> nincs egyezo STH -> exit 1');
  // Meridian-review: az STH aláírt control_size-át kötjük a disclosure-höz - eltérő
  // control_size (root-egyezés mellett is) -> nincs jelölt STH -> exit 1
  const xSize = JSON.parse(fs.readFileSync(discPath, 'utf8')); xSize.control_size = 99;
  const xsPath = path.join(dir, 'xsize.json'); fs.writeFileSync(xsPath, JSON.stringify(xSize) + '\n');
  ok(cli(['control', 'verify-inclusion', xsPath, sthPath, '--key', keyPath]).code === 1, 'eltero control_size (signed commitment) -> nincs egyezo STH -> exit 1');

  // ───────────────────────────────────────────────────────────────────────────
  section('4b. Edge: 1-elemu control-fa (inclusion_proof == [], gyoker == levél)');
  const single = [witnessSet];
  const d0 = control.buildControlDisclosure(single, 0);
  ok(Array.isArray(d0.inclusion_proof) && d0.inclusion_proof.length === 0, '1-elemu fa: ures inclusion_proof');
  ok(d0.control_root_hash === core.leafHash(witnessSet) && control.controlRoot(single) === d0.control_root_hash,
    '1-elemu fa: gyoker == a levél hash-e');
  ok(control.verifyControlDisclosure(d0, d0.control_root_hash).ok, '1-elemu fa: verifyControlDisclosure OK');

  // ───────────────────────────────────────────────────────────────────────────
  section('5. Cross-impl: Python verify_control_disclosure parity');
  if (PYTHON) {
    function pyVerify(p, expectRoot) {
      const code = 'import sys, json, axr_verify as a; d=json.load(open(sys.argv[1])); ' +
        'sys.exit(0 if a.verify_control_disclosure(d, sys.argv[2]) else 1)';
      try { execFileSync(PYTHON, ['-c', code, p, expectRoot], { cwd: __dirname, stdio: 'pipe' }); return 0; }
      catch (e) { return e.status == null ? -1 : e.status; }
    }
    ok(pyVerify(discPath, sth.control_root_hash) === 0, 'Python: ervenyes disclosure -> ok (parity)');
    ok(pyVerify(badPath, sth.control_root_hash) === 1, 'Python: tamperelt disclosure -> elutasitva (parity)');
  } else {
    console.log('  SKIP - nincs Python');
  }

  console.log(`\nOsszesen: ${pass} ok, ${fail} hiba` + (PYTHON ? '' : ' (Python esetek kihagyva)'));
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('VARATLAN HIBA:', e); process.exit(1); });
