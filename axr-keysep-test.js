// ═══════════════════════════════════════════════════════════════════════════════
// AXR - Kulcs-szerep szetvalasztas (receipt-kulcs != STH-kulcs)
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-keysep-test.js
//
// Egy receipt-alairo kulcs kompromittalodasa NE tegye hamisithatova a fa-fejeket
// (STH), es forditva. A horgonyzo sidecar az STH-t egy KULON kulccsal irja ala;
// a verifier --sth-key kapcsoloval kapja meg. Bizonyitando:
//   1. kulon STH-kulccsal alairt log + --sth-key -> verifier 0
//   2. ugyanaz a log --sth-key NELKUL (a fo kulcsot probalja az STH-ra) -> 1
//   3. ha valaki egy MAS kulccsal ujraalairja az STH-t (a megadott sth-key-tol
//      eltero) -> --sth-key alatt is 1
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
const { runAnchor } = require('./axr-anchor');

let passed = 0;
async function check(name, fn) {
  try { await fn(); passed++; console.log(`  ok  - ${name}`); }
  catch (e) { console.log(`  HIBA - ${name}\n        ${e.message}`); process.exitCode = 1; }
}

function kp() {
  const k = crypto.generateKeyPairSync('ed25519');
  return { priv: k.privateKey.export({ type: 'pkcs8', format: 'pem' }),
           pub: k.publicKey.export({ type: 'spki', format: 'pem' }) };
}

const rec = kp();   // receipt-alairo
const sth = kp();   // STH-alairo (kulon)
const sign = (o) => { const r = { ...o }; delete r.signature; r.signature = core.signReceipt(r, rec.priv); return r; };

function buildReceipts(dir) {
  const wfId = core.uuid();
  const s = sign({
    axr_version: '0.4', receipt_type: 'step', receipt_id: core.uuid(),
    workflow_receipt_id: wfId, sequence: 1, timestamp: 't',
    step: { node_name: 'X', node_type: 'code', deterministic: true, model: null },
    io: { input_hash: core.sha256('i'), output_hash: core.sha256('o'), input_summary: {}, decision: { status: 'OK' } },
    previous_receipt_hash: null, anchor_ref: null
  });
  const wf = sign({
    axr_version: '0.4', receipt_type: 'workflow', receipt_id: wfId,
    workflow: { workflow_id: 'w', workflow_version: '1', webhook_path: 'p', trigger_timestamp: 't', completion_timestamp: 't' },
    actor: { agent_id: 'a', agent_type: 'n8n-workflow', operator: 'op', on_behalf_of: 'c', identity_ref: null },
    request: { input_hash: core.sha256('r'), customer_ref: core.customerRef('a', 'b', 'c') },
    outcome: { final_status: 'OK', decision_summary: 'ok' },
    step_chain: [s.receipt_id], chain_root_hash: core.chainHash(s),
    previous_receipt_hash: null, anchor_ref: null
  });
  fs.writeFileSync(path.join(dir, 'receipts.jsonl'), [s, wf].map(r => JSON.stringify(r)).join('\n') + '\n');
  fs.writeFileSync(path.join(dir, 'receipt-pub.pem'), rec.pub);
  fs.writeFileSync(path.join(dir, 'sth-pub.pem'), sth.pub);
}

function runVerify(dir, sthKeyPath) {
  const args = [path.join(__dirname, 'axr-verify.js'), path.join(dir, 'receipts.jsonl'),
    path.join(dir, 'receipt-pub.pem'), path.join(dir, 'sth.jsonl'), path.join(dir, 'anchors.jsonl')];
  if (sthKeyPath) args.push('--sth-key', sthKeyPath);
  try { return { code: 0, out: execFileSync('node', args, { encoding: 'utf8' }) }; }
  catch (e) { return { code: e.status == null ? -1 : e.status, out: (e.stdout || '').toString() }; }
}

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-ks-'));
  buildReceipts(dir);
  // a horgonyzas az STH-t a KULON sth-kulccsal irja ala
  await runAnchor({ receiptsPath: path.join(dir, 'receipts.jsonl'), privateKeyPem: sth.priv,
    sthPath: path.join(dir, 'sth.jsonl'), anchorsPath: path.join(dir, 'anchors.jsonl'),
    backends: ['local'], now: () => '2026-06-08T08:00:02.000Z' });

  await check('kulon STH-kulccsal + --sth-key -> verifier 0', () => {
    const res = runVerify(dir, path.join(dir, 'sth-pub.pem'));
    assert.strictEqual(res.code, 0, `nem 0:\n${res.out}`);
    assert.ok(/kulcs-szerep szetvalasztva/.test(res.out), 'az osszegzes nem jelzi a szetvalasztast');
  });

  await check('--sth-key NELKUL (fo kulcs az STH-ra) -> verifier 1', () => {
    const res = runVerify(dir, null);
    assert.strictEqual(res.code, 1, `a hibas STH-kulcsot nem fogta el:\n${res.out}`);
    assert.ok(/STH.*ERVENYTELEN ALAIRAS/.test(res.out), 'nem az STH-alairast jelezte');
  });

  await check('idegen kulccsal ujraalairt STH + --sth-key -> verifier 1', () => {
    const other = kp();
    const sthLines = fs.readFileSync(path.join(dir, 'sth.jsonl'), 'utf8').trim().split('\n');
    const sthObj = JSON.parse(sthLines[0]);
    delete sthObj.signature;
    sthObj.signature = core.signReceipt(sthObj, other.priv); // nem a megadott sth-key
    const d2 = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-ks2-'));
    buildReceipts(d2);
    fs.copyFileSync(path.join(dir, 'anchors.jsonl'), path.join(d2, 'anchors.jsonl'));
    fs.writeFileSync(path.join(d2, 'sth.jsonl'), JSON.stringify(sthObj) + '\n');
    const res = runVerify(d2, path.join(d2, 'sth-pub.pem'));
    assert.strictEqual(res.code, 1, `az idegen-kulcsu STH-t nem utasitotta el:\n${res.out}`);
    fs.rmSync(d2, { recursive: true, force: true });
  });

  fs.rmSync(dir, { recursive: true, force: true });
  console.log('-'.repeat(72));
  if (process.exitCode === 1) {
    console.log(`EREDMENY: NEM minden teszt zold (${passed} sikeres). Lasd a [HIBA] sorokat.`);
  } else {
    console.log(`EREDMENY: mind a ${passed} teszt zold. A kulcs-szerep szetvalasztas mukodik.`);
  }
})();
