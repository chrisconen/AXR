// ═══════════════════════════════════════════════════════════════════════════════
// AXR 1.4 - Witness-felfuggesztes (ideiglenes, auto-lejaro) record + idovonal + e2e
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-witness-suspension-test.js   (Python esetek kihagyva, ha nincs)
//
// Mit ellenoriz:
//   1. witness_suspension record build/verify (egykulcsos + kvorum; tampering;
//      strukturalis hibak - until>from; idegen root -> elutasitas)
//   2. Idovonal + suspendedWitnessesAt ablak [from,until) + AUTO-LEJARAS;
//      revokacio-PRECEDENCIA (revoked+suspended -> revoked nyer)
//   3. JOINDULATU: 3-witness/threshold-2 - egy felfuggesztett witness alatt is
//      teljesul a kuszob -> WITNESS_SUSPENDED NOTICE, NINCS violation (monitor ok,
//      verifier exit 0 meg --require-witnesses mellett is)
//   4. Kuszob ala vivo felfuggesztes -> UNDER_WITNESSED (notice default,
//      --require-witnesses mellett violation), de NEM WITNESS_* violation
//   5. Red-team: hamis/idegen-log witness_suspension -> CONTROL_ROOT_MISMATCH
//   6. Backward-kompat: felfuggesztes nelkul valtozatlan
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

const T0 = () => '2026-06-13T14:30:00.000Z';
const LOG = 'axr:witness-suspend:v1';
const root = genKey(), op = genKey(), W1 = genKey(), W2 = genKey(), W3 = genKey();
const W3fp = s.keyFingerprint(W3.publicKey);

const trustRoot = s.buildTrustRoot({ providers: [],
  logs: [{ log_id: LOG, genesis: { sth: op.publicKey, receipt: op.publicKey } }] },
  root.privateKey, root.publicKey, T0);
// 3-witness keszlet, threshold 2 (egy felfuggesztett witness alatt is teljesul)
const ws3 = s.buildWitnessSet({ log_id: LOG, witness_threshold: 2, effective_from_tree_size: 1,
  witnesses: [{ name: 'a', public_key: W1.publicKey }, { name: 'b', public_key: W2.publicKey },
              { name: 'c', public_key: W3.publicKey }] }, root.privateKey, T0);
// 2-witness keszlet, threshold 2 (felfuggesztes -> kuszob ala)
const ws2 = s.buildWitnessSet({ log_id: LOG, witness_threshold: 2, effective_from_tree_size: 1,
  witnesses: [{ name: 'a', public_key: W1.publicKey }, { name: 'b', public_key: W2.publicKey }] }, root.privateKey, T0);

let prevWf = null;
function sign(obj) { const r = { ...obj }; delete r.signature; r.signature = axr.signReceipt(r, op.privateKey); return r; }
function appendRun(p, tag) {
  const wfId = axr.uuid(); const steps = []; let prev = null;
  for (let i = 0; i < 2; i++) {
    const st = sign({ axr_version: '0.3', receipt_type: 'step', receipt_id: axr.uuid(),
      workflow_receipt_id: wfId, sequence: i + 1, timestamp: T0(),
      step: { node_name: `N${i}`, node_type: 'n8n-nodes-base.code', kind: 'deterministic', deterministic: true, model: null },
      io: { input_hash: axr.sha256(`${tag}-in-${i}`), output_hash: axr.sha256(`${tag}-out-${i}`), input_summary: {}, decision: null },
      inputs: [], approval: null, previous_receipt_hash: prev, anchor_ref: null });
    steps.push(st); prev = axr.chainHash(st);
  }
  const wf = sign({ axr_version: '0.3', receipt_type: 'workflow', receipt_id: wfId,
    workflow: { workflow_id: 'wf', workflow_version: '1', webhook_path: 'p', trigger_timestamp: T0(), completion_timestamp: T0() },
    actor: { agent_id: 'a', agent_type: 'n8n-workflow', operator: 'op', on_behalf_of: 'c', identity_ref: null },
    request: { input_hash: axr.sha256(`${tag}-raw`), customer_ref: axr.customerRef('a', 'b', 'c') },
    outcome: { final_status: tag, available: false, decision_summary: tag },
    step_chain: steps.map(x => x.receipt_id), chain_root_hash: axr.chainHash(steps[steps.length - 1]),
    approval: null, previous_receipt_hash: prevWf, anchor_ref: null });
  prevWf = axr.chainHash(wf);
  fs.appendFileSync(p, [...steps, wf].map(r => JSON.stringify(r)).join('\n') + '\n');
}
function readSths(p) { return fs.readFileSync(p, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse); }

// Ket runbol allo log (STH1 tree_size=3, STH2 tree_size=6); a megadott witness_set
// a control logban; mindket STH-t a megadott kulcsok cosignoljak.
async function buildLog(dir, witnessSetRec, cosignKeys, extraControl) {
  prevWf = null;
  const receiptsPath = path.join(dir, 'receipts.jsonl');
  const sthPath = path.join(dir, 'sth.jsonl');
  const trPath = path.join(dir, 'trust-root.json');
  const controlPath = path.join(dir, 'control.jsonl');
  const keyPath = path.join(dir, 'op.pem');
  fs.writeFileSync(trPath, JSON.stringify(trustRoot) + '\n');
  fs.writeFileSync(controlPath, JSON.stringify(witnessSetRec) + '\n');
  for (const rec of (extraControl || [])) fs.appendFileSync(controlPath, JSON.stringify(rec) + '\n');
  fs.writeFileSync(keyPath, op.publicKey);
  fs.writeFileSync(receiptsPath, '');
  const base = { receiptsPath, sthPath, anchorsPath: path.join(dir, 'anchors.jsonl'),
    backends: ['local'], logId: LOG, now: T0, controlPath, controlTrustRootPath: trPath };
  appendRun(receiptsPath, 'RUN1');
  await runAnchor({ ...base, privateKeyPem: op.privateKey });
  appendRun(receiptsPath, 'RUN2');
  await runAnchor({ ...base, privateKeyPem: op.privateKey });
  const out = readSths(sthPath).map(sth => sth.record_type === 'sth'
    ? s.assembleWitnessCosignatures(sth, cosignKeys.map(pk => s.cosignWitness(sth, pk))) : sth);
  fs.writeFileSync(sthPath, out.map(r => JSON.stringify(r)).join('\n') + '\n');
  return { receiptsPath, sthPath, anchorsPath: base.anchorsPath, trPath, controlPath, keyPath,
    control: () => fs.readFileSync(controlPath, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse) };
}
function runVerify(cmd, L, extra) {
  const script = cmd === 'node' ? 'axr-verify.js' : 'axr_verify.py';
  const args = [path.join(__dirname, script), L.receiptsPath, L.keyPath, L.sthPath, L.anchorsPath,
    '--trust-root', L.trPath, '--control', L.controlPath, ...(extra || [])];
  try { execFileSync(cmd, args, { stdio: 'pipe' }); return { code: 0, out: '' }; }
  catch (e) { return { code: e.status == null ? -1 : e.status, out: (e.stdout || '') + (e.stderr || '') }; }
}

(async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-wsus-'));
  const mkdir = (n) => { const d = path.join(tmp, n); fs.mkdirSync(d); return d; };

  // ─────────────────────────────────────────────────────────────────────────
  section('1. witness_suspension record build/verify');
  const sus = s.buildWitnessSuspension({ log_id: LOG, suspended_fingerprint: W3fp, suspended_from_tree_size: 6, suspended_until_tree_size: 9, reason: 'maintenance' }, root.privateKey);
  ok(sus.record_type === 'witness_suspension' && sus.suspended_fingerprint === W3fp, 'a record alakja helyes');
  ok(s.verifyWitnessSuspension(sus, root.publicKey).ok, 'verify a root publikus kulccsal: OK');
  ok(s.verifyWitnessSuspension(sus, trustRoot).ok, 'verify a trust-root objektummal: OK');
  ok(!s.verifyWitnessSuspension({ ...sus, suspended_until_tree_size: 600 }, root.publicKey).ok, 'tampered (until atirva) -> ERVENYTELEN');
  ok(!s.verifyWitnessSuspension(sus, genKey().publicKey).ok, 'idegen root-kulcs -> ERVENYTELEN');
  let threw = false;
  try { s.buildWitnessSuspensionBody({ log_id: LOG, suspended_fingerprint: W3fp, suspended_from_tree_size: 9, suspended_until_tree_size: 9 }); } catch (e) { threw = true; }
  ok(threw, 'strukturalis hiba (until <= from) -> dobas a build-nel');
  // kvorum
  const r2 = genKey(), r3 = genKey();
  const quorumTr = s.buildQuorumTrustRoot({ providers: [], root_keys: [r2.publicKey, r3.publicKey], threshold: 2,
    logs: [{ log_id: LOG, genesis: { sth: op.publicKey, receipt: op.publicKey } }] }, [r2.privateKey, r3.privateKey], T0);
  const qsus = s.buildQuorumWitnessSuspension({ log_id: LOG, suspended_fingerprint: W3fp, suspended_from_tree_size: 6, suspended_until_tree_size: 9 }, [r2.privateKey, r3.privateKey]);
  ok(s.verifyWitnessSuspension(qsus, quorumTr).ok, 'kvorum-alairt witness_suspension verifikal a kvorum-root ellen');

  // ─────────────────────────────────────────────────────────────────────────
  section('2. Idovonal + suspendedWitnessesAt ablak + auto-lejaras + revokacio-precedencia');
  const wtl = s.buildWitnessTimeline([ws3], trustRoot, [], [sus]);
  ok(wtl.suspensions.length === 1 && wtl.suspensions[0].fingerprint === W3fp && wtl.suspensions[0].from === 6 && wtl.suspensions[0].until === 9,
    'a timeline visszaadja a felfuggesztest {fingerprint, from, until}');
  ok(s.suspendedWitnessesAt(wtl.suspensions, 3).size === 0, 'tree_size=3 (<6): W3 nincs felfuggesztve');
  ok(s.suspendedWitnessesAt(wtl.suspensions, 6).has(W3fp), 'tree_size=6 ([6,9)): W3 felfuggesztve');
  ok(s.suspendedWitnessesAt(wtl.suspensions, 8).has(W3fp), 'tree_size=8 ([6,9)): W3 meg felfuggesztve');
  ok(s.suspendedWitnessesAt(wtl.suspensions, 9).size === 0, 'tree_size=9 (until exkluziv): W3 AUTO-LEJART, ujra szamit');
  // revokacio-precedencia: W3 revokalt 6-tol ES felfuggesztett [6,9) - a revokacio nyer
  const rev = s.buildWitnessRevocation({ log_id: LOG, revoked_fingerprint: W3fp, revoked_at_tree_size: 6 }, root.privateKey);
  let sthX = { axr_version: '0.3', record_type: 'sth', log_id: LOG, tree_size: 6,
    root_hash: 'sha256:' + crypto.createHash('sha256').update('r6').digest('hex'), timestamp: T0(), previous_sth_hash: null };
  sthX.signature = axr.signReceipt(sthX, op.privateKey);
  sthX = s.assembleWitnessCosignatures(sthX, [W1, W2, W3].map(k => s.cosignWitness(sthX, k.privateKey)));
  const we = s.witnessAt(wtl.timeline, 6);
  const rset = s.revokedWitnessesAt([{ fingerprint: W3fp, from_tree_size: 6 }], 6);
  const sset = s.suspendedWitnessesAt(wtl.suspensions, 6);
  const wr = s.verifyWitnessCosignatures(sthX, we, rset, sset);
  ok(wr.revoked.length === 1 && wr.revoked[0] === W3fp && wr.suspended.length === 0,
    'precedencia: revoked+suspended fingerprint -> REVOKED-kent kezelve (suspended NEM)');
  // Meridian-review: felfuggesztett DE nem-deklaralt / ervenytelen-alairasu cosig
  // NEM bujhat at benign WITNESS_SUSPENDED-kent - anomalia marad.
  const Wx = genKey(), Wxfp = s.keyFingerprint(Wx.publicKey);
  let sthU = { axr_version: '0.3', record_type: 'sth', log_id: LOG, tree_size: 6,
    root_hash: 'sha256:' + crypto.createHash('sha256').update('rU').digest('hex'), timestamp: T0(), previous_sth_hash: null };
  sthU.signature = axr.signReceipt(sthU, op.privateKey);
  sthU = s.assembleWitnessCosignatures(sthU, [W1, W2, Wx].map(k => s.cosignWitness(sthU, k.privateKey)));
  const wrU = s.verifyWitnessCosignatures(sthU, we, new Set(), new Set([Wxfp]));
  ok(wrU.anomalies.some(a => /nem-deklaralt/.test(a)) && wrU.suspended.length === 0,
    'felfuggesztett DE nem-deklaralt witness -> anomalia (nem benign suspended)');
  // deklaralt (W3) + ervenytelen alairas + felfuggesztett -> anomalia, nem suspended
  let sthInv = { axr_version: '0.3', record_type: 'sth', log_id: LOG, tree_size: 6,
    root_hash: 'sha256:' + crypto.createHash('sha256').update('rI').digest('hex'), timestamp: T0(), previous_sth_hash: null };
  sthInv.signature = axr.signReceipt(sthInv, op.privateKey);
  sthInv = s.assembleWitnessCosignatures(sthInv, [W1, W2, W3].map(k => s.cosignWitness(sthInv, k.privateKey)));
  const w3cos = sthInv.witness_cosignatures.find(c => c.witness_fingerprint === W3fp);
  w3cos.signature = Buffer.from('z'.repeat(64)).toString('base64');   // elrontott alairas
  const wrInv = s.verifyWitnessCosignatures(sthInv, we, new Set(), new Set([W3fp]));
  ok(wrInv.anomalies.some(a => /ERVENYTELEN/.test(a)) && !wrInv.suspended.includes(W3fp),
    'felfuggesztett DE ervenytelen-alairasu (deklaralt) witness -> anomalia (nem benign suspended)');

  // ─────────────────────────────────────────────────────────────────────────
  section('3. JOINDULATU: 3-witness/threshold-2, W3 felfuggesztve [6,9) -> notice, NINCS violation');
  const L3 = await buildLog(mkdir('benign'), ws3, [W1.privateKey, W2.privateKey, W3.privateKey], [sus]);
  const m3 = pollMonitor({ sthPath: L3.sthPath, publicKeyPem: op.publicKey, statePath: path.join(tmp, 'm3.json'),
    receiptsPath: L3.receiptsPath, trustRoot: [trustRoot], control: L3.control(), requireWitnesses: true, now: T0 });
  ok(m3.ok, 'monitor (--require-witnesses): OK - a felfuggesztes NEM violation (kuszob teljesul: 2/2)');
  ok(/WITNESS_SUSPENDED/.test(m3.notices.join(' | ')), 'WITNESS_SUSPENDED notice megjelenik (a 6-os STH-n)');
  ok(!codes(m3).includes('WITNESS_REVOKED') && !codes(m3).includes('WITNESS_COSIGNATURE_INVALID'),
    'NINCS WITNESS_REVOKED / WITNESS_COSIGNATURE_INVALID');
  ok(runVerify('node', L3, ['--require-witnesses']).code === 0, 'JS verifier --require-witnesses: exit 0 (felfuggesztes joindulatu)');
  if (PYTHON) ok(runVerify(PYTHON, L3, ['--require-witnesses']).code === 0, 'Python verifier --require-witnesses: exit 0 (cross-impl)');

  // ─────────────────────────────────────────────────────────────────────────
  section('4. Kuszob ala vivo felfuggesztes -> UNDER_WITNESSED (nem WITNESS_* violation)');
  const susW2 = s.buildWitnessSuspension({ log_id: LOG, suspended_fingerprint: s.keyFingerprint(W2.publicKey), suspended_from_tree_size: 6, suspended_until_tree_size: 9 }, root.privateKey);
  const L4 = await buildLog(mkdir('under'), ws2, [W1.privateKey, W2.privateKey], [susW2]);
  const m4 = pollMonitor({ sthPath: L4.sthPath, publicKeyPem: op.publicKey, statePath: path.join(tmp, 'm4.json'),
    receiptsPath: L4.receiptsPath, trustRoot: [trustRoot], control: L4.control(), now: T0 });
  ok(m4.ok && /UNDER_WITNESSED/.test(m4.notices.join(' | ')) && /WITNESS_SUSPENDED/.test(m4.notices.join(' | ')),
    'default: UNDER_WITNESSED + WITNESS_SUSPENDED notice, NINCS violation');
  const m4r = pollMonitor({ sthPath: L4.sthPath, publicKeyPem: op.publicKey, statePath: path.join(tmp, 'm4r.json'),
    receiptsPath: L4.receiptsPath, trustRoot: [trustRoot], control: L4.control(), requireWitnesses: true, now: T0 });
  ok(!m4r.ok && codes(m4r).includes('UNDER_WITNESSED'), '--require-witnesses: UNDER_WITNESSED violation (a kuszob ala esett)');
  ok(runVerify('node', L4).code === 0 && runVerify('node', L4, ['--require-witnesses']).code === 1,
    'JS verifier: default exit 0, --require-witnesses exit 1');

  // ─────────────────────────────────────────────────────────────────────────
  section('5. Red-team: hamis / idegen-log witness_suspension -> CONTROL_ROOT_MISMATCH');
  const forged = { ...sus, signature: Buffer.from('x'.repeat(64)).toString('base64') };
  const Lf = await buildLog(mkdir('forged'), ws3, [W1.privateKey, W2.privateKey, W3.privateKey], null);
  fs.appendFileSync(Lf.controlPath, JSON.stringify(forged) + '\n');
  const mf = pollMonitor({ sthPath: Lf.sthPath, publicKeyPem: op.publicKey, statePath: path.join(tmp, 'mf.json'),
    receiptsPath: Lf.receiptsPath, trustRoot: [trustRoot], control: Lf.control(), now: T0 });
  ok(!mf.ok && codes(mf).includes('CONTROL_ROOT_MISMATCH'), 'monitor: hamis witness_suspension -> CONTROL_ROOT_MISMATCH');
  const jf = runVerify('node', Lf);
  ok(jf.code === 1 && /CONTROL_ROOT_MISMATCH/.test(jf.out), 'JS verifier: hamis -> exit 1 + CONTROL_ROOT_MISMATCH');
  const foreign = s.buildWitnessSuspension({ log_id: 'axr:OTHER:v1', suspended_fingerprint: W3fp, suspended_from_tree_size: 6, suspended_until_tree_size: 9 }, root.privateKey);
  const Lfor = await buildLog(mkdir('foreign'), ws3, [W1.privateKey, W2.privateKey, W3.privateKey], null);
  fs.appendFileSync(Lfor.controlPath, JSON.stringify(foreign) + '\n');
  const jfor = runVerify('node', Lfor);
  ok(jfor.code === 1 && /CONTROL_ROOT_MISMATCH/.test(jfor.out), 'JS verifier: idegen-log witness_suspension -> exit 1 + CONTROL_ROOT_MISMATCH');
  if (PYTHON) ok(runVerify(PYTHON, Lfor).code === 1, 'Python verifier: idegen-log -> exit 1 (cross-impl)');

  // ─────────────────────────────────────────────────────────────────────────
  section('6. Backward-kompat: felfuggesztes nelkul valtozatlan');
  const Lok = await buildLog(mkdir('ok'), ws3, [W1.privateKey, W2.privateKey, W3.privateKey], null);
  const mok = pollMonitor({ sthPath: Lok.sthPath, publicKeyPem: op.publicKey, statePath: path.join(tmp, 'mok.json'),
    receiptsPath: Lok.receiptsPath, trustRoot: [trustRoot], control: Lok.control(), requireWitnesses: true, now: T0 });
  ok(mok.ok && !/WITNESS_SUSPENDED/.test(mok.notices.join(' | ')), 'felfuggesztes nelkul: OK, nincs WITNESS_SUSPENDED');
  ok(runVerify('node', Lok, ['--require-witnesses']).code === 0, 'JS verifier --require-witnesses: exit 0');

  console.log(`\nOsszesen: ${pass} ok, ${fail} hiba` + (PYTHON ? '' : ' (Python esetek kihagyva)'));
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('VARATLAN HIBA:', e); process.exit(1); });
