// ═══════════════════════════════════════════════════════════════════════════════
// AXR - --strict mod (puha jelzesek CI-kapuva emelese)
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-strict-test.js
//
// A "puha" jelzesek nem feltetlen manipulacio (lehet konfiguracios hiany vagy
// minosegi gyengeseg), ezert default modban csak figyelmeztetes (verifier 0).
// --strict alatt viszont HIBA (verifier 1) - egy CI-kapunak ez kell.
//
// Mit ellenoriz egy null input_hash-u (hianyzo __axr_input marker) lancon:
//   1. default mod -> verifier 0 (megjegyzes, de atmegy)
//   2. --strict    -> verifier 1 (a puha jelzes hibava emelve)
//   3. az ep (marker-hiany nelkuli) lanc --strict alatt is 0
//
// Nulla kulso fuggoseg.  Kilepesi kod: 0 ha minden zold, 1 ha barmi megbukik.
// ═══════════════════════════════════════════════════════════════════════════════

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const core = require('./axr-core');

let passed = 0;
function check(name, fn) {
  try { fn(); passed++; console.log(`  ok  - ${name}`); }
  catch (e) { console.log(`  HIBA - ${name}\n        ${e.message}`); process.exitCode = 1; }
}

const k = crypto.generateKeyPairSync('ed25519');
const priv = k.privateKey.export({ type: 'pkcs8', format: 'pem' });
const pub = k.publicKey.export({ type: 'spki', format: 'pem' });
const sign = (o) => { const r = { ...o }; delete r.signature; r.signature = core.signReceipt(r, priv); return r; };

// Ket 0.2 lepes; az egyik input_hash-e null (a node nem hagyott __axr_input markert).
// Eltero output_hash-ek, hogy az "uniform input_hash" (mas) ellenorzes ne lojjon.
function buildLog(nullMarker) {
  const wfId = core.uuid();
  const s1 = sign({
    axr_version: '0.2', receipt_type: 'step', receipt_id: core.uuid(),
    workflow_receipt_id: wfId, sequence: 1, timestamp: '2026-06-08T08:00:00.000Z',
    step: { node_name: 'Normalize', node_type: 'code', deterministic: true, model: null },
    io: { input_hash: core.sha256('a'), output_hash: core.sha256('o1'), input_summary: {}, decision: null },
    previous_receipt_hash: null, anchor_ref: null
  });
  const s2 = sign({
    axr_version: '0.2', receipt_type: 'step', receipt_id: core.uuid(),
    workflow_receipt_id: wfId, sequence: 2, timestamp: '2026-06-08T08:00:00.000Z',
    step: { node_name: 'Decide', node_type: 'code', deterministic: true, model: null },
    io: { input_hash: nullMarker ? null : core.sha256('b'),
          output_hash: core.sha256('o2'), input_summary: {}, decision: { status: 'OK' } },
    previous_receipt_hash: core.chainHash(s1), anchor_ref: null
  });
  const wf = sign({
    axr_version: '0.2', receipt_type: 'workflow', receipt_id: wfId,
    workflow: { workflow_id: 'wf', workflow_version: '1', webhook_path: 'p', trigger_timestamp: 't', completion_timestamp: 't' },
    actor: { agent_id: 'a', agent_type: 'n8n-workflow', operator: 'op', on_behalf_of: 'c', identity_ref: null },
    request: { input_hash: core.sha256('raw'), customer_ref: core.customerRef('a', 'b', 'c') },
    outcome: { final_status: 'OK', decision_summary: 'ok' },
    step_chain: [s1.receipt_id, s2.receipt_id], chain_root_hash: core.chainHash(s2),
    previous_receipt_hash: null, anchor_ref: null
  });
  return [s1, s2, wf];
}

function runVerify(receipts, strict) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-strict-'));
  fs.writeFileSync(path.join(dir, 'public-key.pem'), pub);
  fs.writeFileSync(path.join(dir, 'receipts.jsonl'), receipts.map(r => JSON.stringify(r)).join('\n') + '\n');
  const args = [path.join(__dirname, 'axr-verify.js'), path.join(dir, 'receipts.jsonl'), path.join(dir, 'public-key.pem')];
  if (strict) args.push('--strict');
  let r;
  try { r = { code: 0, out: execFileSync('node', args, { encoding: 'utf8' }) }; }
  catch (e) { r = { code: e.status == null ? -1 : e.status, out: (e.stdout || '').toString() }; }
  fs.rmSync(dir, { recursive: true, force: true });
  return r;
}

check('null input_hash, default mod -> verifier 0 (megjegyzes)', () => {
  const res = runVerify(buildLog(true), false);
  assert.strictEqual(res.code, 0, `default modban nem 0:\n${res.out}`);
  assert.ok(/input_hash-e null/.test(res.out), 'nem jelezte a null input_hash-t');
});

check('null input_hash, --strict -> verifier 1 (hibava emelve)', () => {
  const res = runVerify(buildLog(true), true);
  assert.strictEqual(res.code, 1, `--strict alatt nem 1:\n${res.out}`);
  assert.ok(/\(strict\)/.test(res.out), 'nem strict-hibakent jelezte');
});

check('ep lanc (van marker) --strict alatt is -> verifier 0', () => {
  const res = runVerify(buildLog(false), true);
  assert.strictEqual(res.code, 0, `az ep lanc --strict alatt megbukott:\n${res.out}`);
});

console.log('-'.repeat(72));
if (process.exitCode === 1) {
  console.log(`EREDMENY: NEM minden teszt zold (${passed} sikeres). Lasd a [HIBA] sorokat.`);
} else {
  console.log(`EREDMENY: mind a ${passed} teszt zold. A --strict mod (CI-kapu) mukodik.`);
}
