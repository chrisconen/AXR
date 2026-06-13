// ═══════════════════════════════════════════════════════════════════════════════
// AXR - Compliance Report Generator teszt
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-report-test.js
//
// Mit ellenoriz:
//   1. buildReportModel: a modell mezoi helyesek egy valodi (termelesi uton
//      epitett) logra; a compliance-control tabla jelen
//   2. A verdikt EGYEZIK az axr-verify.js-szel: valid log -> a CLI exit 0 + a
//      riport PASS; tamper -> exit 1 + FAIL (a riport nem allit tobbet, mint
//      amit a verifier bizonyit)
//   3. HTML well-formed-szeru (doctype, banner, a kontroll-tabla sorai),
//      JSON parse-olhato
//   4. Rotalt log: a kulcs-governance idovonal megjelenik a modellben
//      (genesis + succession, role-onkent)
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
const report = require('./axr-report');

let pass = 0, fail = 0;
function ok(cond, name) { if (cond) { pass++; } else { fail++; console.log('  FAIL: ' + name); } }
function section(t) { console.log('\n' + t); }

function genKey() {
  const kp = crypto.generateKeyPairSync('ed25519');
  return { privateKey: kp.privateKey.export({ type: 'pkcs8', format: 'pem' }),
           publicKey: kp.publicKey.export({ type: 'spki', format: 'pem' }) };
}
const T0 = () => '2026-06-13T08:00:00.000Z';
const LOG = 'axr:report-test:v1';
const root = genKey(), sthA = genKey(), sthB = genKey(), Rc1 = genKey();

const trustRoot = s.buildTrustRoot({ providers: [],
  logs: [{ log_id: LOG, genesis: { sth: sthA.publicKey, receipt: Rc1.publicKey } }] },
  root.privateKey, root.publicKey, T0);
const sthSucc = s.buildKeySuccession({ log_id: LOG, role: 'sth',
  predecessor_fingerprint: s.keyFingerprint(sthA.publicKey), successor_public_key: sthB.publicKey,
  effective_from_tree_size: 4 }, root.privateKey, T0);

function sign(obj, privPem) { const r = { ...obj }; delete r.signature; r.signature = axr.signReceipt(r, privPem); return r; }
function makeRun(privPem, prev, tag) {
  const wfId = axr.uuid(); const steps = []; let p = null;
  for (let i = 0; i < 2; i++) {
    const st = sign({ axr_version: '0.3', receipt_type: 'step', receipt_id: axr.uuid(),
      workflow_receipt_id: wfId, sequence: i + 1, timestamp: T0(),
      step: { node_name: `N${i}`, node_type: 'n8n-nodes-base.code', kind: 'deterministic', deterministic: true, model: null },
      io: { input_hash: axr.sha256(`${tag}-in-${i}`), output_hash: axr.sha256(`${tag}-out-${i}`), input_summary: {}, decision: null },
      inputs: [], approval: null, previous_receipt_hash: p, anchor_ref: null }, privPem);
    steps.push(st); p = axr.chainHash(st);
  }
  const wf = sign({ axr_version: '0.3', receipt_type: 'workflow', receipt_id: wfId,
    workflow: { workflow_id: 'wf', workflow_version: '1', webhook_path: 'p', trigger_timestamp: T0(), completion_timestamp: T0() },
    actor: { agent_id: 'a', agent_type: 'n8n-workflow', operator: 'op', on_behalf_of: 'c', identity_ref: null },
    request: { input_hash: axr.sha256(`${tag}-raw`), customer_ref: axr.customerRef('a', 'b', 'c') },
    outcome: { final_status: tag, available: false, decision_summary: tag },
    step_chain: steps.map(x => x.receipt_id), chain_root_hash: axr.chainHash(steps[steps.length - 1]),
    approval: null, previous_receipt_hash: prev || null, anchor_ref: null }, privPem);
  return { receipts: [...steps, wf], workflowHash: axr.chainHash(wf) };
}

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-report-'));
  const receiptsPath = path.join(dir, 'receipts.jsonl');
  const sthPath = path.join(dir, 'sth.jsonl');
  const anchorsPath = path.join(dir, 'anchors.jsonl');
  const trPath = path.join(dir, 'trust-root.json');
  const succPath = path.join(dir, 'successions.jsonl');
  const keyPath = path.join(dir, 'sthA.pem');
  fs.writeFileSync(trPath, JSON.stringify(trustRoot) + '\n');
  fs.writeFileSync(succPath, JSON.stringify(sthSucc) + '\n');
  fs.writeFileSync(keyPath, sthA.publicKey);
  const base = { receiptsPath, sthPath, anchorsPath, backends: ['local'], logId: LOG, now: T0 };
  // Rc1 irja a receipteket; sthA majd sthB az STH-kat (rotacio @4)
  const run1 = makeRun(Rc1.privateKey, null, 'OK1');
  fs.writeFileSync(receiptsPath, run1.receipts.map(r => JSON.stringify(r)).join('\n') + '\n');
  await runAnchor({ ...base, privateKeyPem: sthA.privateKey });
  const run2 = makeRun(Rc1.privateKey, run1.workflowHash, 'OK2');
  fs.appendFileSync(receiptsPath, run2.receipts.map(r => JSON.stringify(r)).join('\n') + '\n');
  await runAnchor({ ...base, privateKeyPem: sthB.privateKey, succession: sthSucc });

  const readJsonl = (p) => fs.readFileSync(p, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);

  // ─────────────────────────────────────────────────────────────────────────
  section('1. buildReportModel mezoi');
  const inputs = {
    receipts: readJsonl(receiptsPath), sths: readJsonl(sthPath).filter(r => r.record_type === 'sth'),
    anchors: readJsonl(anchorsPath).filter(r => r.record_type === 'anchor'),
    publicKeyPem: Rc1.publicKey, trustRoot: [trustRoot], successions: [sthSucc],
    logId: LOG, now: T0, verdict: { code: 0, ok: true, source: 'axr-verify.js' }
  };
  const model = report.buildReportModel(inputs);
  ok(model.log.workflows === 2 && model.log.steps === 4, 'log-attekintes: 2 workflow / 4 step');
  ok(model.integrity.signatures_bad === 0 && model.integrity.signatures_ok === 6, 'minden alairas ervenyes (6)');
  ok(model.anchoring.anchored === 6 && model.anchoring.backends.includes('local'), 'anchoring: 6 lehorgonyozva, local backend');
  ok(model.controls.length === 6 && model.controls.some(c => /Art\. 12/.test(c.ref)), 'compliance-control tabla (Art.12 jelen)');
  ok(model.log.log_id === LOG, 'log_id feloldva');

  // ─────────────────────────────────────────────────────────────────────────
  section('2. Rotalt log: kulcs-governance idovonal');
  const sthEvents = model.governance.events.filter(e => e.role === 'sth');
  ok(sthEvents.length === 2 && sthEvents[0].kind === 'genesis' && sthEvents[1].from_tree_size === 4,
    'sth idovonal: genesis + succession @4');
  ok(sthEvents.every(e => e.authorized), 'minden sth-szegmens autorizalt');
  ok(model.governance.active_keys.sth && model.governance.active_keys.sth.authorized,
    'aktiv sth-kulcs autorizalt a legnagyobb fa-meretnel');

  // ─────────────────────────────────────────────────────────────────────────
  section('3. HTML / JSON render');
  const html = report.renderHtml(model);
  ok(/^<!doctype html>/.test(html) && /PASS — VERIFIED/.test(html), 'HTML: doctype + PASS banner');
  ok(/Art\. 12/.test(html) && /Limits/.test(html), 'HTML: kontroll-tabla + Limits szekcio');
  ok(/does not replace independent verification/.test(html), 'HTML: oszinte hatar-szoveg jelen');
  const json = report.renderJson(model);
  const parsed = JSON.parse(json);
  ok(parsed.verdict.ok === true && parsed.governance.events.length >= 2, 'JSON parse-olhato + tartalmazza az idovonalat');
  // FAIL-verdikt rendereles
  const failHtml = report.renderHtml(report.buildReportModel({ ...inputs, verdict: { code: 1, ok: false, source: 'axr-verify.js' } }));
  ok(/FAIL — INTEGRITY VIOLATION/.test(failHtml), 'FAIL-verdikt -> piros banner');

  // ─────────────────────────────────────────────────────────────────────────
  section('4. CLI verdikt EGYEZIK az axr-verify.js-szel');
  function runReport(extra) {
    const args = [path.join(__dirname, 'axr-report.js'), receiptsPath, keyPath, sthPath, anchorsPath,
      '--trust-root', trPath, '--successions', succPath, '--format', 'json', ...(extra || [])];
    try { return { code: 0, out: execFileSync('node', args, { encoding: 'utf8', stdio: 'pipe' }) }; }
    catch (e) { return { code: e.status == null ? -1 : e.status, out: (e.stdout || '').toString() }; }
  }
  function runVerify() {
    const args = [path.join(__dirname, 'axr-verify.js'), receiptsPath, keyPath, sthPath, anchorsPath,
      '--trust-root', trPath, '--successions', succPath];
    try { execFileSync('node', args, { stdio: 'pipe' }); return 0; } catch (e) { return e.status == null ? -1 : e.status; }
  }
  const vClean = runVerify();
  const rClean = runReport();
  ok(vClean === 0 && rClean.code === 0, 'valid log: verifier exit 0 ES riport exit 0');
  ok(JSON.parse(rClean.out).verdict.ok === true, 'a riport JSON verdiktje PASS');

  // tamper: egy receipt tartalmat megvaltoztatjuk (nincs ujra-alairas)
  const recs = readJsonl(receiptsPath);
  recs[recs.length - 1].outcome.final_status = 'HAMISITVA';
  fs.writeFileSync(receiptsPath, recs.map(r => JSON.stringify(r)).join('\n') + '\n');
  const vTamper = runVerify();
  const rTamper = runReport();
  ok(vTamper === 1 && rTamper.code === 1, 'tamper: verifier exit 1 ES riport exit 1 (a verdikt egyezik)');
  ok(JSON.parse(rTamper.out).verdict.ok === false, 'a riport JSON verdiktje FAIL');
  // a riport NEM allit tobbet: a tamper utan a sajat alairas-szamlaloja is jelzi
  ok(JSON.parse(rTamper.out).integrity.signatures_bad >= 1, 'a riport sajat nezete is jelzi a rossz alairast');

  console.log(`\nOsszesen: ${pass} ok, ${fail} hiba`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('VARATLAN HIBA:', e); process.exit(1); });
