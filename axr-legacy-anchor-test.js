#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════════════
// axr-legacy-anchor-test.js - regressziós teszt
// ═══════════════════════════════════════════════════════════════════════════════
// A BUG (2026-06-10, sandbox-fopróba közben találva): a core.signablePart az
// anchor_ref-et csak 0.3+ verziónál vágta le az aláírt részből, miközben a
// 0.3-as horgonyzó sidecar MINDEN frissen lefedett receiptbe visszaírja -
// a 0.1/0.2-es legacy receiptekbe is. Következmény: egy éles 0.2-es log
// lehorgonyzása után a TELJES historikus lánc aláírás-ellenőrzése elbukott.
//
// A FIX: signablePart (JS és Python) jelenlét-alapon vágja le az anchor_ref-et,
// ahogy a chainHash már eddig is - az anchor_ref definíció szerint aláírás
// után íródik, semelyik verzió aláírásának nem része.
//
// EZ A TESZT: 0.2-es logot épít -> sidecar-ral lehorgonyozza (külön STH-kulcs)
// -> a JS ÉS a Python verifiernek is el kell fogadnia -> egy lehorgonyzott
// 0.2-es receipt megpiszkálása után mindkettőnek buknia kell.
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const core = require('./axr-core');

let failures = 0;
function check(name, cond, extra) {
  console.log(`  ${cond ? 'ok ' : 'BUK'} - ${name}${cond || !extra ? '' : ' :: ' + extra}`);
  if (!cond) failures++;
}
const PYTHON = process.platform === 'win32' ? 'python' : 'python3';
function runExit(cmd, args) {
  const actual = cmd === 'python3' ? PYTHON : cmd;
  try { execFileSync(actual, args, { encoding: 'utf8', stdio: 'pipe' }); return 0; }
  catch (e) { return e.status == null ? -1 : e.status; }
}

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-legacy-'));
const recPath = path.join(dir, 'receipts.jsonl');
const sthPath = path.join(dir, 'sth.jsonl');
const ancPath = path.join(dir, 'anchors.jsonl');

// kulcsok: fo alairo + KULON STH-kulcs (kulcs-szerep szetvalasztas)
const main = crypto.generateKeyPairSync('ed25519');
const sth = crypto.generateKeyPairSync('ed25519');
const mainPriv = main.privateKey.export({ type: 'pkcs8', format: 'pem' });
const mainPubPath = path.join(dir, 'public-key.pem');
fs.writeFileSync(mainPubPath, main.publicKey.export({ type: 'spki', format: 'pem' }));
const sthPrivPath = path.join(dir, 'sth-key.pem');
fs.writeFileSync(sthPrivPath, sth.privateKey.export({ type: 'pkcs8', format: 'pem' }));
const sthPubPath = path.join(dir, 'sth-public.pem');
fs.writeFileSync(sthPubPath, sth.publicKey.export({ type: 'spki', format: 'pem' }));

// ── 0.2-es log epitese: 2 workflow-futas, futasonkent 2 step receipt ───────────
// Pontosan a 0.2-es n8n-generator sema szerint (axr_version '0.2', nincs
// anchor_ref alairaskor - a sidecar irja be utolag).
function buildRun(prevWorkflowHash, runIdx) {
  const wfId = core.uuid();
  const now = new Date().toISOString();
  const steps = [];
  let prevStepHash = null;
  for (let s = 1; s <= 2; s++) {
    const body = {
      axr_version: '0.2', receipt_type: 'step', receipt_id: core.uuid(),
      workflow_receipt_id: wfId, sequence: s, timestamp: now,
      step: { node_name: `Node ${s}`, node_type: 'n8n-nodes-base.code',
              logic_version: '1.0', model: null, deterministic: true },
      io: { input_hash: core.sha256({ run: runIdx, s }), output_hash: core.sha256({ out: runIdx, s }),
            input_summary: { run: runIdx }, decision: null },
      approval: null, previous_receipt_hash: prevStepHash
    };
    const rec = { ...body, signature: core.signReceipt(body, mainPriv) };
    prevStepHash = core.sha256(rec);
    steps.push(rec);
  }
  const wfBody = {
    axr_version: '0.2', receipt_type: 'workflow', receipt_id: wfId,
    workflow: { workflow_id: 'legacy-regression', workflow_version: '1.0',
                webhook_path: 'x', trigger_timestamp: now, completion_timestamp: now },
    actor: { agent_id: 'legacy-agent', agent_type: 'n8n-workflow',
             operator: 'Test', on_behalf_of: 'Test' },
    request: { input_hash: core.sha256({ req: runIdx }), customer_ref: core.sha256('x') },
    outcome: { final_status: 'OK', available: true, decision_summary: 'ok' },
    step_chain: steps.map(r => r.receipt_id),
    chain_root_hash: prevStepHash,
    approval: null, previous_receipt_hash: prevWorkflowHash
  };
  const wfRec = { ...wfBody, signature: core.signReceipt(wfBody, mainPriv) };
  return { lines: [...steps, wfRec], wfHash: core.sha256(wfRec) };
}

const run1 = buildRun(null, 1);
const run2 = buildRun(run1.wfHash, 2);
fs.writeFileSync(recPath,
  [...run1.lines, ...run2.lines].map(r => JSON.stringify(r)).join('\n') + '\n');

console.log('axr-legacy-anchor-test - 0.2-es log horgonyzasa nem torheti az alairasokat');
console.log('------------------------------------------------------------------------');

// 0) horgonyzas ELOTT mindket verifier zold (alapallapot)
check('horgonyzas elott: JS verifier elfogad',
  runExit('node', ['axr-verify.js', recPath, mainPubPath]) === 0);
check('horgonyzas elott: Python verifier elfogad',
  runExit('python3', ['axr_verify.py', recPath, mainPubPath]) === 0);

// 1) sidecar-horgonyzas local backenddel, kulon STH-kulccsal
const ancExit = runExit('node', ['axr-anchor.js', recPath, sthPrivPath,
  '--sth', sthPath, '--anchors', ancPath, '--backend', 'local',
  '--log-id', 'axr:legacy-regression:v1']);
check('sidecar lefut a 0.2-es logon', ancExit === 0);
const anchored = fs.readFileSync(recPath, 'utf8').trim().split('\n').map(JSON.parse);
check('a sidecar anchor_ref-et irt a 0.2-es receiptekbe',
  anchored.every(r => r.anchor_ref && r.anchor_ref.sth_root_hash));

// 2) A REGRESSZIO MAGJA: horgonyzas UTAN is zold mindket verifier
check('horgonyzas utan: JS verifier elfogad (a bug itt bukott)',
  runExit('node', ['axr-verify.js', recPath, mainPubPath, sthPath, ancPath,
                   '--sth-key', sthPubPath]) === 0);
check('horgonyzas utan: Python verifier elfogad (tukor-fix)',
  runExit('python3', ['axr_verify.py', recPath, mainPubPath, sthPath, ancPath,
                      '--sth-key', sthPubPath]) === 0);

// 3) kontroll: egy lehorgonyzott 0.2-es receipt megpiszkalasa tovabbra is bukik
const tampered = anchored.map((r, i) =>
  i === 0 ? { ...r, io: { ...r.io, input_summary: { run: 999 } } } : r);
const tamperPath = path.join(dir, 'tampered.jsonl');
fs.writeFileSync(tamperPath, tampered.map(r => JSON.stringify(r)).join('\n') + '\n');
check('tamper-elt horgonyzott log: JS verifier elutasit',
  runExit('node', ['axr-verify.js', tamperPath, mainPubPath, sthPath, ancPath,
                   '--sth-key', sthPubPath]) === 1);
check('tamper-elt horgonyzott log: Python verifier elutasit',
  runExit('python3', ['axr_verify.py', tamperPath, mainPubPath, sthPath, ancPath,
                      '--sth-key', sthPubPath]) === 1);

console.log('------------------------------------------------------------------------');
if (failures === 0) {
  console.log('EREDMENY: mind a(z) 8 teszt zold. A legacy-horgonyzas biztonsagos.');
  process.exit(0);
}
console.log(`EREDMENY: ${failures} teszt BUKOTT.`);
process.exit(1);
