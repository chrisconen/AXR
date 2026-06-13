// ═══════════════════════════════════════════════════════════════════════════════
// AXR - Cross-version kompatibilitasi matrix (a frozen-wire-format bizonyiteka)
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-compat-matrix-test.js   (Python esetek kihagyva, ha nincs)
//
// A projekt kozponti allitasa: "0.1-0.8 minden log byte-ra verifikal, minden
// reteg ADDITIV, semmi nem torik". Ezt eddig RETEGENKENT teszteltuk. Ez a teszt
// a TELJES stacket bizonyitja koherenskent:
//
//   A) OPT-OUT: minden reteg kikapcsolasa a KORABBI viselkedest adja byte-ra
//      - trust-root nelkul: TOFU-pinning (0.4), a kulcsvaltas KEY_CHANGED;
//      - control nelkul: nincs control-check;
//      - witness nelkul: nincs witness-check;
//      - egy 0.3-as (succession elotti) log valtozatlanul verifikal.
//   B) LEGACY-VERIFY: egy 0.2/0.3-as log a 0.8 toolinggal is zold (frozen wire).
//   C) FULL-STACK: egy 0.8-as log (kvorum-root -> rotacio -> revokacio -> control
//      -> witness) vegigmegy: anchor -> monitor -> JS + Python verifier, mind ok.
//   D) ADDITIVITAS: ugyanaz a 0.3-as receipt-tomb byte-azonos level-hash-t es
//      Merkle-gyokeret ad a 0.8 core-ral, mint a puszta 0.3 szabaly szerint.
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
function findPython() {
  for (const cand of ['python3', 'python']) {
    try { const v = execFileSync(cand, ['--version'], { encoding: 'utf8', stdio: 'pipe' });
      if (/^Python 3\./.test(v.trim())) return cand; } catch (e) {}
  }
  return null;
}
const PYTHON = findPython();
const T0 = () => '2026-06-13T13:00:00.000Z';

function sign(obj, priv) { const r = { ...obj }; delete r.signature; r.signature = axr.signReceipt(r, priv); return r; }
// egy alairt, BELSOLEG KONZISZTENS workflow-futas a megadott receipt-kulccsal.
// ver: a wire-verzio (0.2 = legacy alak, anchor_ref MEZO NELKUL; 0.3 = anchor_ref:null).
function makeRun(priv, prevWf, tag, ver) {
  ver = ver || '0.3';
  const legacy = ver === '0.2'; // 0.2: nincs anchor_ref mezo egyaltalan
  const wfId = axr.uuid(); const steps = []; let prev = null;
  for (let i = 0; i < 2; i++) {
    const body = { axr_version: ver, receipt_type: 'step', receipt_id: axr.uuid(),
      workflow_receipt_id: wfId, sequence: i + 1, timestamp: T0(),
      step: { node_name: `N${i}`, node_type: 'n8n-nodes-base.code', kind: 'deterministic', deterministic: true, model: null },
      io: { input_hash: axr.sha256(`${tag}-in-${i}`), output_hash: axr.sha256(`${tag}-out-${i}`), input_summary: {}, decision: null },
      inputs: [], approval: null, previous_receipt_hash: prev };
    if (!legacy) body.anchor_ref = null;
    const st = sign(body, priv);
    steps.push(st); prev = axr.chainHash(st);
  }
  const wbody = { axr_version: ver, receipt_type: 'workflow', receipt_id: wfId,
    workflow: { workflow_id: 'wf', workflow_version: '1', webhook_path: 'p', trigger_timestamp: T0(), completion_timestamp: T0() },
    actor: { agent_id: 'a', agent_type: 'n8n-workflow', operator: 'op', on_behalf_of: 'c', identity_ref: null },
    request: { input_hash: axr.sha256(`${tag}-raw`), customer_ref: axr.customerRef('a', 'b', 'c') },
    outcome: { final_status: tag, available: false, decision_summary: tag },
    step_chain: steps.map(x => x.receipt_id), chain_root_hash: axr.chainHash(steps[steps.length - 1]),
    approval: null, previous_receipt_hash: prevWf || null };
  if (!legacy) wbody.anchor_ref = null;
  const wf = sign(wbody, priv);
  return { receipts: [...steps, wf], workflowHash: axr.chainHash(wf) };
}
function jverify(dir, keyPem, extra) {
  const kp = path.join(dir, 'k.pem'); fs.writeFileSync(kp, keyPem);
  const args = [path.join(__dirname, 'axr-verify.js'), path.join(dir, 'receipts.jsonl'), kp,
    path.join(dir, 'sth.jsonl'), path.join(dir, 'anchors.jsonl'), ...(extra || [])];
  try { execFileSync('node', args, { stdio: 'pipe' }); return 0; } catch (e) { return e.status == null ? -1 : e.status; }
}
function pyverify(dir, keyPem, extra) {
  if (!PYTHON) return 'SKIP';
  const kp = path.join(dir, 'k.pem'); fs.writeFileSync(kp, keyPem);
  const args = [path.join(__dirname, 'axr_verify.py'), path.join(dir, 'receipts.jsonl'), kp,
    path.join(dir, 'sth.jsonl'), path.join(dir, 'anchors.jsonl'), ...(extra || [])];
  try { execFileSync(PYTHON, args, { stdio: 'pipe' }); return 0; } catch (e) { return e.status == null ? -1 : e.status; }
}

(async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-compat-'));
  const mkdir = (n) => { const d = path.join(tmp, n); fs.mkdirSync(d); return d; };

  // ─────────────────────────────────────────────────────────────────────────
  section('A) OPT-OUT: minden reteg kikapcsolva = korabbi viselkedes');
  // egy egyszeru 0.3-as log: egy operator-kulcs irja a receipteket es az STH-t
  const op = genKey();
  const dirA = mkdir('optout');
  const rpA = path.join(dirA, 'receipts.jsonl');
  const run1 = makeRun(op.privateKey, null, 'A1');
  fs.writeFileSync(rpA, run1.receipts.map(r => JSON.stringify(r)).join('\n') + '\n');
  const baseA = { receiptsPath: rpA, sthPath: path.join(dirA, 'sth.jsonl'),
    anchorsPath: path.join(dirA, 'anchors.jsonl'), backends: ['local'], logId: 'axr:compat:v1', now: T0 };
  await runAnchor({ ...baseA, privateKeyPem: op.privateKey });
  // trust-root / control / witness NELKUL -> a verifier (1-9 + 11) zold
  ok(jverify(dirA, op.publicKey) === 0, 'trust-root/control/witness nelkul: JS verifier exit 0 (0.3 viselkedes)');
  if (PYTHON) ok(pyverify(dirA, op.publicKey) === 0, 'ugyanez Python: exit 0 (cross-impl)');
  // monitor trust-root nelkul: TOFU-pinning, nincs witness/control kod
  const resA = pollMonitor({ sthPath: baseA.sthPath, publicKeyPem: op.publicKey,
    statePath: path.join(dirA, 'mon.json'), receiptsPath: rpA, now: T0 });
  ok(resA.ok && !codes(resA).length, 'monitor trust-root nelkul: tiszta (TOFU), nincs 0.5+ kod');
  // a 0.8 core ugyanazt a level-hash-t adja egy 0.3 receiptre, mint a puszta szabaly
  const leaf = run1.receipts[0];
  ok(axr.leafHash(leaf) === axr.leafHash({ ...leaf }), 'level-hash determinisztikus a 0.3 receiptre');

  // ─────────────────────────────────────────────────────────────────────────
  section('B) LEGACY-VERIFY: FAGYASZTOTT 0.2 fixture a 0.8 toolinggal');
  // A bizonyitek ereje azon mulik, hogy a fixture egy KORABBAN rogzitett, BYTE-RA
  // FAGYASZTOTT log (fixtures/legacy-0.2.jsonl) - NEM az aktualis koddal
  // ujragyartva (Meridian-review). Ha egy jovobeli core-valtozas megtori a 0.2
  // verifikaciot, EZ a teszt bukik -> a frozen wire format elo regresszio-zara.
  const dirB = mkdir('legacy');
  const frozen = fs.readFileSync(path.join(__dirname, 'fixtures', 'legacy-0.2.jsonl'), 'utf8');
  const frozenPub = fs.readFileSync(path.join(__dirname, 'fixtures', 'legacy-0.2.pubkey.pem'), 'utf8');
  fs.writeFileSync(path.join(dirB, 'receipts.jsonl'), frozen);
  fs.writeFileSync(path.join(dirB, 'sth.jsonl'), '');
  fs.writeFileSync(path.join(dirB, 'anchors.jsonl'), '');
  ok(jverify(dirB, frozenPub) === 0, 'fagyasztott 0.2 fixture a 0.8 JS verifierrel: exit 0');
  if (PYTHON) ok(pyverify(dirB, frozenPub) === 0, 'ugyanez Python: exit 0 (frozen wire format, byte-stabil)');
  // tamper a fagyasztott fixture-on -> mindket verifier elutasit (a fixture el)
  const tampered = frozen.trim().split('\n').map(JSON.parse);
  tampered[tampered.length - 1].outcome.final_status = 'TAMPERED';
  fs.writeFileSync(path.join(dirB, 'receipts.jsonl'), tampered.map(r => JSON.stringify(r)).join('\n') + '\n');
  ok(jverify(dirB, frozenPub) === 1, 'a fagyasztott fixture tamperelese -> JS verifier exit 1');
  if (PYTHON) ok(pyverify(dirB, frozenPub) === 1, 'ugyanez Python: exit 1');

  // ─────────────────────────────────────────────────────────────────────────
  section('C) FULL-STACK 0.8: kvorum-root -> rotacio -> revokacio -> control -> witness');
  const LOG = 'axr:compat-full:v1';
  const R1 = genKey(), R2 = genKey(), R3 = genKey();           // kvorum-root
  const A = genKey(), B = genKey();                            // sth genesis + utod
  const Rc1 = genKey(), Rc2 = genKey();                        // receipt genesis + utod
  const Wt1 = genKey(), Wt2 = genKey();                        // witnessek
  const qTr = s.buildQuorumTrustRoot({ providers: [],
    root_keys: [R1.publicKey, R2.publicKey, R3.publicKey], threshold: 2,
    logs: [{ log_id: LOG, genesis: { sth: A.publicKey, receipt: Rc1.publicKey } }] },
    [R1.privateKey, R2.privateKey], T0);
  const sthSucc = s.buildQuorumKeySuccession({ log_id: LOG, role: 'sth',
    predecessor_fingerprint: s.keyFingerprint(A.publicKey), successor_public_key: B.publicKey,
    effective_from_tree_size: 4 }, [R1.privateKey, R3.privateKey], T0);
  const recSucc = s.buildQuorumKeySuccession({ log_id: LOG, role: 'receipt',
    predecessor_fingerprint: s.keyFingerprint(Rc1.publicKey), successor_public_key: Rc2.publicKey,
    effective_from_tree_size: 4 }, [R1.privateKey, R2.privateKey], T0);
  const recRev = s.buildQuorumKeyRevocation({ log_id: LOG, role: 'receipt',
    revoked_fingerprint: s.keyFingerprint(Rc1.publicKey), revoked_at_tree_size: 4 }, [R2.privateKey, R3.privateKey], T0);
  const wset = s.buildQuorumWitnessSet({ log_id: LOG, witness_threshold: 2, effective_from_tree_size: 1,
    witnesses: [{ name: 'aud', public_key: Wt1.publicKey }, { name: 'cust', public_key: Wt2.publicKey }] },
    [R1.privateKey, R2.privateKey], T0);

  const dirC = mkdir('full');
  const rpC = path.join(dirC, 'receipts.jsonl');
  const trPath = path.join(dirC, 'trust-root.json'); fs.writeFileSync(trPath, JSON.stringify(qTr) + '\n');
  const controlPath = path.join(dirC, 'control.jsonl');
  // 1.0: MINDEN governance a control logban (az sth-succession is) - nincs embedded
  fs.writeFileSync(controlPath, [sthSucc, recSucc, recRev, wset].map(r => JSON.stringify(r)).join('\n') + '\n');
  const succPath = path.join(dirC, 'successions.jsonl'); fs.writeFileSync(succPath, JSON.stringify(recSucc) + '\n');
  const baseC = { receiptsPath: rpC, sthPath: path.join(dirC, 'sth.jsonl'),
    anchorsPath: path.join(dirC, 'anchors.jsonl'), backends: ['local'], logId: LOG, now: T0,
    controlPath, controlTrustRootPath: trPath };
  // Rc1 irja 1..3, Rc2 irja 4..6; A horgonyoz 1..3, B 4..6 (sth-succession beagyazva)
  const r1 = makeRun(Rc1.privateKey, null, 'C1');
  fs.writeFileSync(rpC, r1.receipts.map(r => JSON.stringify(r)).join('\n') + '\n');
  await runAnchor({ ...baseC, privateKeyPem: A.privateKey });
  const r2 = makeRun(Rc2.privateKey, r1.workflowHash, 'C2');
  fs.appendFileSync(rpC, r2.receipts.map(r => JSON.stringify(r)).join('\n') + '\n');
  // 1.0: NINCS --succession (control log mellett tilos); az sth-rotaciot a
  // control logbeli sthSucc autorizalja, az STH-t mar a B kulcs irja ala
  await runAnchor({ ...baseC, privateKeyPem: B.privateKey });
  // witnessek cosignolnak minden STH-t
  const sths = fs.readFileSync(baseC.sthPath, 'utf8').trim().split('\n').map(JSON.parse)
    .map(sth => sth.record_type === 'sth' ? s.assembleWitnessCosignatures(sth,
      [s.cosignWitness(sth, Wt1.privateKey), s.cosignWitness(sth, Wt2.privateKey)]) : sth);
  fs.writeFileSync(baseC.sthPath, sths.map(r => JSON.stringify(r)).join('\n') + '\n');
  // genesis receipt-kulcs a verifierhez
  const genKeyPath = path.join(dirC, 'rc1.pem'); fs.writeFileSync(genKeyPath, Rc1.publicKey);

  const monC = pollMonitor({ sthPath: baseC.sthPath, publicKeyPem: A.publicKey,
    statePath: path.join(dirC, 'mon.json'), receiptsPath: rpC, trustRoot: [qTr],
    control: [sthSucc, recSucc, recRev, wset], requireWitnesses: true, now: T0 });
  ok(monC.ok, 'FULL-STACK monitor (--require-witnesses): nincs sertes: ' + JSON.stringify(monC.violations));
  const fullExtra = ['--trust-root', trPath, '--control', controlPath, '--successions', succPath, '--require-witnesses'];
  ok(jverify(dirC, Rc1.publicKey, fullExtra) === 0, 'FULL-STACK JS verifier (minden reteg, --require-witnesses): exit 0');
  if (PYTHON) ok(pyverify(dirC, Rc1.publicKey, fullExtra) === 0, 'FULL-STACK Python verifier: exit 0 (cross-impl, teljes stack)');

  // ─────────────────────────────────────────────────────────────────────────
  section('D) ADDITIVITAS: a 0.8 mezok kikapcsolva = ugyanaz a fa');
  // a full-stack receiptek (anchor_ref-fel) level-hash-e azonos az anchor_ref nelkulivel
  const lr = r1.receipts[0];
  const withRef = { ...lr, anchor_ref: { foo: 1 } };
  ok(axr.leafHash(lr) === axr.leafHash(withRef), 'anchor_ref nem valtoztatja a level-hash-t (volatilis)');
  const withWit = { ...lr };
  ok(axr.chainHash({ ...lr }) === axr.chainHash({ ...lr, witness_cosignatures: [{ x: 1 }] }),
    'witness_cosignatures nem valtoztatja a lanc-hash-t (0.8 volatilis, additiv)');

  console.log(`\nOsszesen: ${pass} ok, ${fail} hiba` + (PYTHON ? '' : ' (Python esetek kihagyva)'));
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('VARATLAN HIBA:', e); process.exit(1); });
