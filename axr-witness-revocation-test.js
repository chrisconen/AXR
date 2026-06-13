// ═══════════════════════════════════════════════════════════════════════════════
// AXR 1.1 - Emergency witness-revokacio (record + idovonal + monitor/verifier e2e)
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-witness-revocation-test.js   (Python esetek kihagyva, ha nincs)
//
// Mit ellenoriz:
//   1. witness_revocation record build/verify (egykulcsos + kvorum; tampering;
//      strukturalis hibak; idegen root -> elutasitas)
//   2. Idovonal + revokedWitnessesAt + verifyWitnessCosignatures (2-szintu szabaly,
//      legkorabbi hatar nyer fingerprintenkent, revokalt cosig nem szamit a kuszobba)
//   3. Monitor + JS/Python verifier e2e: a hatar utan a revokalt witness
//      cosignature-je WITNESS_REVOKED (mindig violation), es a kuszob ala viszi a
//      log-ot (UNDER_WITNESSED). A hatar ELOTT a cosignature meg szamit.
//   4. Red-team: hamis (root-ala-nem-irt) witness_revocation a control logban ->
//      CONTROL_ROOT_MISMATCH (monitor + verifier).
//   5. Backward-kompat: witness_revocation NELKUL a viselkedes valtozatlan.
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
const LOG = 'axr:witness-revoke:v1';
const root = genKey(), op = genKey(), W1 = genKey(), W2 = genKey(), W3 = genKey();

const trustRoot = s.buildTrustRoot({ providers: [],
  logs: [{ log_id: LOG, genesis: { sth: op.publicKey, receipt: op.publicKey } }] },
  root.privateKey, root.publicKey, T0);
const witnessSet = s.buildWitnessSet({ log_id: LOG, witness_threshold: 2, effective_from_tree_size: 1,
  witnesses: [{ name: 'auditor', public_key: W1.publicKey }, { name: 'customer', public_key: W2.publicKey }] },
  root.privateKey, T0);
const W2fp = s.keyFingerprint(W2.publicKey);

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

// Ket runbol allo log (STH1 tree_size=3, STH2 tree_size=6), mindket STH-t W1+W2
// cosignolja; a control log a witness_set + (opcionalis) extra rekordok.
async function buildLog(dir, extraControl) {
  prevWf = null;
  const receiptsPath = path.join(dir, 'receipts.jsonl');
  const sthPath = path.join(dir, 'sth.jsonl');
  const trPath = path.join(dir, 'trust-root.json');
  const controlPath = path.join(dir, 'control.jsonl');
  const keyPath = path.join(dir, 'op.pem');
  fs.writeFileSync(trPath, JSON.stringify(trustRoot) + '\n');
  fs.writeFileSync(controlPath, JSON.stringify(witnessSet) + '\n');
  for (const rec of (extraControl || [])) fs.appendFileSync(controlPath, JSON.stringify(rec) + '\n');
  fs.writeFileSync(keyPath, op.publicKey);
  fs.writeFileSync(receiptsPath, '');
  const base = { receiptsPath, sthPath, anchorsPath: path.join(dir, 'anchors.jsonl'),
    backends: ['local'], logId: LOG, now: T0, controlPath, controlTrustRootPath: trPath };
  appendRun(receiptsPath, 'RUN1');
  await runAnchor({ ...base, privateKeyPem: op.privateKey });
  appendRun(receiptsPath, 'RUN2');
  await runAnchor({ ...base, privateKeyPem: op.privateKey });
  // mindket STH-t W1+W2 cosignolja
  const out = readSths(sthPath).map(sth => sth.record_type === 'sth'
    ? s.assembleWitnessCosignatures(sth, [s.cosignWitness(sth, W1.privateKey), s.cosignWitness(sth, W2.privateKey)]) : sth);
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
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-wrev-'));
  const mkdir = (n) => { const d = path.join(tmp, n); fs.mkdirSync(d); return d; };

  // ─────────────────────────────────────────────────────────────────────────
  section('1. witness_revocation record build/verify');
  const rev = s.buildWitnessRevocation({ log_id: LOG, revoked_fingerprint: W2fp, revoked_at_tree_size: 6, reason: 'compromise' }, root.privateKey);
  ok(rev.record_type === 'witness_revocation' && rev.revoked_fingerprint === W2fp, 'a record alakja helyes');
  ok(s.verifyWitnessRevocation(rev, root.publicKey).ok, 'verify a root publikus kulccsal: OK');
  ok(s.verifyWitnessRevocation(rev, trustRoot).ok, 'verify a trust-root objektummal: OK');
  const tampered = { ...rev, revoked_at_tree_size: 1 };
  ok(!s.verifyWitnessRevocation(tampered, root.publicKey).ok, 'tampered (revoked_at atirva) -> ERVENYTELEN');
  const foreignRoot = genKey();
  ok(!s.verifyWitnessRevocation(rev, foreignRoot.publicKey).ok, 'idegen root-kulcs -> ERVENYTELEN');
  ok(!s.verifyWitnessRevocation({ log_id: LOG, record_type: 'witness_revocation', revoked_fingerprint: W2fp, revoked_at_tree_size: 0 }, root.publicKey).ok,
    'strukturalis hiba (revoked_at < 1) -> ERVENYTELEN');
  // kvorum (2-of-2)
  const r2 = genKey(), r3 = genKey();
  const quorumTr = s.buildQuorumTrustRoot({ providers: [], root_keys: [r2.publicKey, r3.publicKey], threshold: 2,
    logs: [{ log_id: LOG, genesis: { sth: op.publicKey, receipt: op.publicKey } }] }, [r2.privateKey, r3.privateKey], T0);
  const qrev = s.buildQuorumWitnessRevocation({ log_id: LOG, revoked_fingerprint: W2fp, revoked_at_tree_size: 6 }, [r2.privateKey, r3.privateKey]);
  ok(s.verifyWitnessRevocation(qrev, quorumTr).ok, 'kvorum-alairt witness_revocation verifikal a kvorum-root ellen');
  ok(!s.verifyWitnessRevocation(s.buildQuorumWitnessRevocation({ log_id: LOG, revoked_fingerprint: W2fp, revoked_at_tree_size: 6 }, [r2.privateKey]), quorumTr).ok,
    'kvorum alatti (1-of-2) witness_revocation -> ERVENYTELEN');

  // ─────────────────────────────────────────────────────────────────────────
  section('2. Idovonal + revokedWitnessesAt + 2-szintu szabaly (unit)');
  const wtl = s.buildWitnessTimeline([witnessSet], trustRoot, [rev]);
  ok(wtl.revocations.length === 1 && wtl.revocations[0].fingerprint === W2fp && wtl.revocations[0].from_tree_size === 6,
    'a timeline visszaadja a revokaciot {fingerprint, from_tree_size}');
  ok(s.revokedWitnessesAt(wtl.revocations, 3).size === 0, 'tree_size=3 (<6): W2 MEG NEM revokalt');
  ok(s.revokedWitnessesAt(wtl.revocations, 6).has(W2fp), 'tree_size=6 (>=6): W2 revokalt');
  // legkorabbi hatar nyer fingerprintenkent
  const revLate = s.buildWitnessRevocation({ log_id: LOG, revoked_fingerprint: W2fp, revoked_at_tree_size: 9 }, root.privateKey);
  const wtl2 = s.buildWitnessTimeline([witnessSet], trustRoot, [revLate, rev]);
  ok(wtl2.revocations[0].from_tree_size === 6, 'tobb revokacio ugyanarra a fingerprintre -> a legkorabbi hatar nyer (6)');
  // verifyWitnessCosignatures revoked-halmazzal: a revokalt cosig nem szamit
  const we = s.witnessAt(wtl.timeline, 6);
  // egy STH-t epitunk W1+W2 cosignature-rel
  let sth = { axr_version: '0.3', record_type: 'sth', log_id: LOG, tree_size: 6,
    root_hash: 'sha256:' + crypto.createHash('sha256').update('r6').digest('hex'), timestamp: T0(), previous_sth_hash: null };
  sth.signature = axr.signReceipt(sth, op.privateKey);
  sth = s.assembleWitnessCosignatures(sth, [s.cosignWitness(sth, W1.privateKey), s.cosignWitness(sth, W2.privateKey)]);
  const noRev = s.verifyWitnessCosignatures(sth, we);
  ok(noRev.validCount === 2 && noRev.revoked.length === 0, 'revokacio nelkul: 2/2 ervenyes');
  const withRev = s.verifyWitnessCosignatures(sth, we, s.revokedWitnessesAt(wtl.revocations, 6));
  ok(withRev.validCount === 1 && withRev.revoked.length === 1 && withRev.revoked[0] === W2fp,
    'revokacioval: W2 nem szamit (1/2 ervenyes), W2 a revoked listaban; a threshold valtozatlan (2)');

  // ─────────────────────────────────────────────────────────────────────────
  section('3. Monitor + verifier e2e: revokacio a 6-os hatartol');
  const L = await buildLog(mkdir('rev'), [rev]);
  const r3mon = pollMonitor({ sthPath: L.sthPath, publicKeyPem: op.publicKey, statePath: path.join(tmp, 'mon3.json'),
    receiptsPath: L.receiptsPath, trustRoot: [trustRoot], control: L.control(), now: T0 });
  ok(!r3mon.ok && codes(r3mon).includes('WITNESS_REVOKED'),
    'monitor (default modban is): a hatar utan revokalt witness cosig -> WITNESS_REVOKED violation');
  ok(/UNDER_WITNESSED/.test(r3mon.notices.join(' | ')) && /1\/2/.test(r3mon.notices.join(' | ')),
    'a revokacio a kuszob ala viszi a 6-os STH-t (1/2 UNDER_WITNESSED notice default modban)');
  ok(!r3mon.violations.some(v => v.code === 'WITNESS_REVOKED' && /tree_size=3/.test(v.message)),
    'a 3-as (hatar elotti) STH-n NINCS WITNESS_REVOKED (a cosig ott meg szamit)');
  const js3 = runVerify('node', L);
  ok(js3.code === 1 && /WITNESS_REVOKED/.test(js3.out), 'JS verifier: exit 1 + WITNESS_REVOKED (--require-witnesses nelkul is)');
  if (PYTHON) {
    const py3 = runVerify(PYTHON, L);
    ok(py3.code === 1 && /WITNESS_REVOKED/.test(py3.out), 'Python verifier: exit 1 + WITNESS_REVOKED (cross-impl)');
  }

  // ─────────────────────────────────────────────────────────────────────────
  section('4. Red-team: hamis (root-ala-nem-irt) witness_revocation');
  // A sidecar commit ELOTT verifikalja a control-rekordokat (self-lockout vedelem),
  // ezert hamis rekordot nem lehet anchorolni - a tamadasi ut a control log
  // UTOLAGOS bovitese. Tiszta logot epitunk, majd a hamis rekordot hozzafuzzuk.
  const forged = { ...rev, signature: Buffer.from('x'.repeat(64)).toString('base64') };
  const Lforged = await buildLog(mkdir('forged'), null);
  fs.appendFileSync(Lforged.controlPath, JSON.stringify(forged) + '\n');
  const r4 = pollMonitor({ sthPath: Lforged.sthPath, publicKeyPem: op.publicKey, statePath: path.join(tmp, 'mon4.json'),
    receiptsPath: Lforged.receiptsPath, trustRoot: [trustRoot], control: Lforged.control(), now: T0 });
  ok(!r4.ok && codes(r4).includes('CONTROL_ROOT_MISMATCH'),
    'monitor: hamis witness_revocation a control logban -> CONTROL_ROOT_MISMATCH (fail-closed)');
  // Meridian-review: a verifier is CONTROL_ROOT_MISMATCH kodot adjon (ne csak exit 1)
  const js4 = runVerify('node', Lforged);
  ok(js4.code === 1 && /CONTROL_ROOT_MISMATCH/.test(js4.out), 'JS verifier: hamis witness_revocation -> exit 1 + CONTROL_ROOT_MISMATCH');
  if (PYTHON) {
    const py4 = runVerify(PYTHON, Lforged);
    ok(py4.code === 1 && /CONTROL_ROOT_MISMATCH/.test(py4.out), 'Python verifier: hamis witness_revocation -> exit 1 + CONTROL_ROOT_MISMATCH (cross-impl)');
  }

  // Meridian-review: idegen-log witness_revocation (ERVENYES root-alairas, de mas
  // log_id) NEM kerulhet az idovonalba - trust boundary. Mindharom fogyasztoban
  // CONTROL_ROOT_MISMATCH (a monitor mar szurt; a verifier mostantol szinten).
  section('4b. Idegen-log witness governance (azonos root, mas log_id) -> CONTROL_ROOT_MISMATCH');
  const foreignRev = s.buildWitnessRevocation({ log_id: 'axr:OTHER:v1', revoked_fingerprint: W2fp, revoked_at_tree_size: 1 }, root.privateKey);
  const Lforeign = await buildLog(mkdir('foreign'), null);
  fs.appendFileSync(Lforeign.controlPath, JSON.stringify(foreignRev) + '\n');
  const r4b = pollMonitor({ sthPath: Lforeign.sthPath, publicKeyPem: op.publicKey, statePath: path.join(tmp, 'mon4b.json'),
    receiptsPath: Lforeign.receiptsPath, trustRoot: [trustRoot], control: Lforeign.control(), now: T0 });
  ok(!r4b.ok && codes(r4b).includes('CONTROL_ROOT_MISMATCH'), 'monitor: idegen-log witness_revocation -> CONTROL_ROOT_MISMATCH');
  const js4b = runVerify('node', Lforeign);
  ok(js4b.code === 1 && /CONTROL_ROOT_MISMATCH/.test(js4b.out), 'JS verifier: idegen-log witness_revocation -> exit 1 + CONTROL_ROOT_MISMATCH');
  if (PYTHON) {
    const py4b = runVerify(PYTHON, Lforeign);
    ok(py4b.code === 1 && /CONTROL_ROOT_MISMATCH/.test(py4b.out), 'Python verifier: idegen-log witness_revocation -> exit 1 + CONTROL_ROOT_MISMATCH (cross-impl)');
  }

  // ─────────────────────────────────────────────────────────────────────────
  section('5. Backward-kompat: witness_revocation NELKUL valtozatlan');
  const Lok = await buildLog(mkdir('ok'), null);
  const r5 = pollMonitor({ sthPath: Lok.sthPath, publicKeyPem: op.publicKey, statePath: path.join(tmp, 'mon5.json'),
    receiptsPath: Lok.receiptsPath, trustRoot: [trustRoot], control: Lok.control(), requireWitnesses: true, now: T0 });
  ok(r5.ok, 'revokacio nelkul, W1+W2 cosignol -> monitor (--require-witnesses) OK, semmi WITNESS_REVOKED');
  ok(runVerify('node', Lok, ['--require-witnesses']).code === 0, 'JS verifier --require-witnesses: exit 0');
  if (PYTHON) ok(runVerify(PYTHON, Lok, ['--require-witnesses']).code === 0, 'Python verifier --require-witnesses: exit 0 (cross-impl)');

  // ─────────────────────────────────────────────────────────────────────────
  section('6. Tobb witness egyideju revokacioja + kvorum-revokacio a control-uton (NEXUS-review)');
  // 3-witness keszlet, threshold 2; W1 es W3 revokalva kulonbozo hataroktol.
  const ws3 = s.buildWitnessSet({ log_id: LOG, witness_threshold: 2, effective_from_tree_size: 1,
    witnesses: [{ name: 'a', public_key: W1.publicKey }, { name: 'b', public_key: W2.publicKey }, { name: 'c', public_key: W3.publicKey }] },
    root.privateKey, T0);
  const W1fp = s.keyFingerprint(W1.publicKey), W3fp = s.keyFingerprint(W3.publicKey);
  const revW1 = s.buildWitnessRevocation({ log_id: LOG, revoked_fingerprint: W1fp, revoked_at_tree_size: 4 }, root.privateKey);
  const revW3 = s.buildWitnessRevocation({ log_id: LOG, revoked_fingerprint: W3fp, revoked_at_tree_size: 8 }, root.privateKey);
  const wtlM = s.buildWitnessTimeline([ws3], trustRoot, [revW1, revW3]);
  ok(wtlM.revocations.length === 2, 'ket kulonbozo witness revokacioja -> 2 bejegyzes az idovonalban');
  ok(s.revokedWitnessesAt(wtlM.revocations, 3).size === 0, 'tree_size=3: egyik sem revokalt');
  ok(s.revokedWitnessesAt(wtlM.revocations, 4).has(W1fp) && !s.revokedWitnessesAt(wtlM.revocations, 4).has(W3fp),
    'tree_size=4: csak W1 revokalt');
  const rev8 = s.revokedWitnessesAt(wtlM.revocations, 8);
  ok(rev8.has(W1fp) && rev8.has(W3fp), 'tree_size=8: W1 ES W3 is revokalt (parhuzamosan kovetve)');
  // kvorum-alairt witness_revocation a control-uton (control.verifyControlRecord)
  const control = require('./axr-control');
  ok(control.verifyControlRecord(qrev, quorumTr, LOG).ok,
    'kvorum-alairt witness_revocation atmegy a control-log verifikacion (verifyControlRecord)');
  ok(!control.verifyControlRecord({ ...qrev, log_id: 'axr:OTHER:v1' }, quorumTr, LOG).ok,
    'idegen log_id-ju kvorum witness_revocation -> a control-verifikacio elutasitja');

  console.log(`\nOsszesen: ${pass} ok, ${fail} hiba` + (PYTHON ? '' : ' (Python esetek kihagyva)'));
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('VARATLAN HIBA:', e); process.exit(1); });
