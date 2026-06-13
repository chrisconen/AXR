// ═══════════════════════════════════════════════════════════════════════════════
// AXR SDK - axr.verify() (programozott teljes-log verifikacio) teszt
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-sdk-verify-test.js
//
// Mit ellenoriz:
//   1. Ervenyes log -> ok:true, exitCode 0, nincs problems
//   2. Tamperelt receipt -> ok:false, exitCode 1, problems nem ures
//   3. NON-DIVERGENCIA: az SDK exitCode-ja BIT-RE egyezik a kozvetlenul futtatott
//      kanonikus CLI exit-kodjaval (ugyanazon bemeneten, ervenyes ES tamperelt)
//   4. Hasznalat/IO hiba (hianyzo fajl) -> ok:false, exitCode 2
//   5. Hianyzo kotelezo opts -> reject
//
// Nulla kulso fuggoseg.  Kilepesi kod: 0 zold, 1 hiba.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const axr = require('./index.js');
const core = require('./axr-core');
const { runAnchor } = require('./axr-anchor');

let pass = 0, fail = 0;
function ok(cond, name) { if (cond) { pass++; } else { fail++; console.log('  FAIL: ' + name); } }
function section(t) { console.log('\n' + t); }
function genKey() {
  const kp = crypto.generateKeyPairSync('ed25519');
  return { privateKey: kp.privateKey.export({ type: 'pkcs8', format: 'pem' }),
           publicKey: kp.publicKey.export({ type: 'spki', format: 'pem' }) };
}
const T0 = () => '2026-06-13T15:30:00.000Z';
const op = genKey();
function sign(obj) { const r = { ...obj }; delete r.signature; r.signature = core.signReceipt(r, op.privateKey); return r; }

// Egy minimalis, alairt, horgonyzott log felepitese egy konyvtarban.
async function buildLog(dir) {
  fs.mkdirSync(dir, { recursive: true });
  const receiptsPath = path.join(dir, 'receipts.jsonl');
  const sthPath = path.join(dir, 'sth.jsonl');
  const anchorsPath = path.join(dir, 'anchors.jsonl');
  const keyPath = path.join(dir, 'pub.pem');
  fs.writeFileSync(keyPath, op.publicKey);
  const wfId = crypto.randomUUID();
  let prev = null; const steps = [];
  for (let i = 0; i < 2; i++) {
    const st = sign({ axr_version: '0.3', receipt_type: 'step', receipt_id: crypto.randomUUID(),
      workflow_receipt_id: wfId, sequence: i + 1, timestamp: T0(),
      step: { node_name: `N${i}`, node_type: 'n8n-nodes-base.code', kind: 'deterministic', deterministic: true, model: null },
      io: { input_hash: core.sha256(`in-${i}`), output_hash: core.sha256(`out-${i}`), input_summary: {}, decision: null },
      inputs: [], approval: null, previous_receipt_hash: prev, anchor_ref: null });
    steps.push(st); prev = core.chainHash(st);
  }
  const wf = sign({ axr_version: '0.3', receipt_type: 'workflow', receipt_id: wfId,
    workflow: { workflow_id: 'wf', workflow_version: '1', webhook_path: 'p', trigger_timestamp: T0(), completion_timestamp: T0() },
    actor: { agent_id: 'a', agent_type: 'n8n-workflow', operator: 'op', on_behalf_of: 'c', identity_ref: null },
    request: { input_hash: core.sha256('raw'), customer_ref: core.customerRef('a', 'b', 'c') },
    outcome: { final_status: 'DONE', available: false, decision_summary: 'x' },
    step_chain: steps.map(x => x.receipt_id), chain_root_hash: core.chainHash(steps[steps.length - 1]),
    approval: null, previous_receipt_hash: null, anchor_ref: null });
  fs.writeFileSync(receiptsPath, [...steps, wf].map(r => JSON.stringify(r)).join('\n') + '\n');
  await runAnchor({ receiptsPath, sthPath, anchorsPath, backends: ['local'], logId: 'axr:sdkverify:v1', now: T0, privateKeyPem: op.privateKey });
  return { receiptsPath, sthPath, anchorsPath, keyPath };
}
// kozvetlen CLI-futas ugyanazon bemeneten (a non-divergencia referenciaja)
function cliExit(L) {
  try { execFileSync(process.execPath, [path.join(__dirname, 'axr-verify.js'), L.receiptsPath, L.keyPath, L.sthPath, L.anchorsPath], { stdio: 'pipe' }); return 0; }
  catch (e) { return e.status == null ? -1 : e.status; }
}

(async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-sdkv-'));

  // ───────────────────────────────────────────────────────────────────────────
  section('1. Ervenyes log -> ok');
  const L = await buildLog(path.join(tmp, 'ok'));
  const r1 = await axr.verify({ receipts: L.receiptsPath, publicKey: L.keyPath, sth: L.sthPath, anchors: L.anchorsPath });
  ok(r1.ok === true && r1.exitCode === 0, 'ervenyes log -> ok:true, exitCode 0');
  ok(Array.isArray(r1.problems) && r1.problems.length === 0, 'nincs problems');
  ok(typeof r1.output === 'string' && /ERVENYES/.test(r1.output), 'output tartalmazza a verdiktet');
  ok(r1.exitCode === cliExit(L), 'NON-DIVERGENCIA: SDK exitCode === kozvetlen CLI exitCode (ervenyes)');

  // ───────────────────────────────────────────────────────────────────────────
  section('2. Tamperelt receipt -> nem ok');
  const Lt = await buildLog(path.join(tmp, 'tamper'));
  const recs = fs.readFileSync(Lt.receiptsPath, 'utf8').trim().split('\n').map(JSON.parse);
  const step = recs.find(r => r.receipt_type === 'step');
  step.io.input_summary.tamper = 'HAMIS';                 // alairas utan, nincs ujra-alairas
  fs.writeFileSync(Lt.receiptsPath, recs.map(r => JSON.stringify(r)).join('\n') + '\n');
  const r2 = await axr.verify({ receipts: Lt.receiptsPath, publicKey: Lt.keyPath, sth: Lt.sthPath, anchors: Lt.anchorsPath });
  ok(r2.ok === false && r2.exitCode === 1, 'tamperelt log -> ok:false, exitCode 1');
  ok(r2.problems.length > 0, 'problems nem ures (a verifikalo [HIBA] sorai kigyujtve)');
  ok(r2.exitCode === cliExit(Lt), 'NON-DIVERGENCIA: SDK exitCode === kozvetlen CLI exitCode (tamperelt)');

  // ───────────────────────────────────────────────────────────────────────────
  section('3. Hasznalat/IO hiba + hianyzo opts');
  const r3 = await axr.verify({ receipts: path.join(tmp, 'nincs.jsonl'), publicKey: L.keyPath });
  ok(r3.ok === false && r3.exitCode === 2, 'hianyzo receipt-fajl -> ok:false, exitCode 2');
  let rejected = false;
  try { await axr.verify({ publicKey: L.keyPath }); } catch (e) { rejected = true; }
  ok(rejected, 'hianyzo kotelezo opts (receipts) -> reject');

  console.log(`\nOsszesen: ${pass} ok, ${fail} hiba`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('VARATLAN HIBA:', e); process.exit(1); });
