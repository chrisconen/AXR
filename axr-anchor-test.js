// ═══════════════════════════════════════════════════════════════════════════════
// AXR 0.3 Stage B - a horgonyzo sidecar tesztje
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-anchor-test.js
//
// Mit ellenoriz (vegpontok kozott, a 'local' backenddel - offline zold):
//   1. ures STH-lancbol elso futas -> uj STH + minden level lehorgonyozva
//   2. a kulonallo verifier elfogadja az igy keletkezett logot (kilepesi kod 0)
//   3. idempotencia: ujabb futas uj level nelkul NEM keletkeztet STH-t
//   4. inkrementalis: egy uj workflow-futas hozzafuzese utani horgonyzas uj,
//      az elozohoz lancolt STH-t ad, a consistency proof tart, es a verifier
//      tovabbra is 0-val zar (a regi receiptek a sajat STH-jukra mutatnak)
//   5. az anchor_ref visszairasa NEM rontja el a receipt-alairast
//
// Nulla kulso fuggoseg.  Kilepesi kod: 0 ha minden zold, 1 ha barmi megbukik.
// ═══════════════════════════════════════════════════════════════════════════════

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const axr = require('./axr-core');
const { runAnchor } = require('./axr-anchor');

let passed = 0;
function check(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => { passed++; console.log(`  ok  - ${name}`); })
    .catch(e => { console.log(`  HIBA - ${name}\n        ${e.message}`); process.exitCode = 1; });
}

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
const pubPem = publicKey.export({ type: 'spki', format: 'pem' });

function sign(obj) {
  const r = { ...obj }; delete r.signature;
  r.signature = axr.signReceipt(r, privPem);
  return r;
}

// Egy teljes workflow-futas: 2 lepes + 1 workflow receipt, helyesen lancolva.
// prevWorkflowHash: az elozo workflow receipt lanc-hash-e (kereszt-futas lanc).
function makeRun(prevWorkflowHash, statusTag) {
  const wfId = axr.uuid();
  const steps = [];
  let prev = null;
  for (let i = 0; i < 2; i++) {
    const base = {
      axr_version: '0.3', receipt_type: 'step', receipt_id: axr.uuid(),
      workflow_receipt_id: wfId, sequence: i + 1, timestamp: '2026-06-06T08:00:00.000Z',
      step: { node_name: `Node ${i}`, node_type: 'n8n-nodes-base.code', kind: 'deterministic',
              deterministic: true, model: null },
      io: { input_hash: axr.sha256(`${statusTag}-in-${i}`), output_hash: axr.sha256(`${statusTag}-out-${i}`),
            input_summary: { idx: i }, decision: null },
      inputs: [], approval: null, previous_receipt_hash: prev, anchor_ref: null
    };
    const s = sign(base);
    steps.push(s);
    prev = axr.chainHash(s);
  }
  const wf = sign({
    axr_version: '0.3', receipt_type: 'workflow', receipt_id: wfId,
    workflow: { workflow_id: 'wf', workflow_version: '5.0', webhook_path: 'p',
                trigger_timestamp: '2026-06-06T08:00:00.000Z', completion_timestamp: '2026-06-06T08:00:00.456Z' },
    actor: { agent_id: 'agent', agent_type: 'n8n-workflow', operator: 'op', on_behalf_of: 'cust', identity_ref: null },
    request: { input_hash: axr.sha256(`${statusTag}-raw`), customer_ref: axr.customerRef('a', 'b', 'c') },
    outcome: { final_status: statusTag, available: false, decision_summary: statusTag },
    step_chain: steps.map(s => s.receipt_id),
    chain_root_hash: axr.chainHash(steps[steps.length - 1]),
    approval: null, previous_receipt_hash: prevWorkflowHash || null, anchor_ref: null
  });
  return { leafReceipts: [...steps, wf], workflowHash: axr.chainHash(wf) };
}

function runVerifier(dir) {
  const kp = path.join(dir, 'public-key.pem');
  fs.writeFileSync(kp, pubPem);
  try {
    execFileSync('node', [
      path.join(__dirname, 'axr-verify.js'),
      path.join(dir, 'receipts.jsonl'), kp,
      path.join(dir, 'sth.jsonl'), path.join(dir, 'anchors.jsonl')
    ], { stdio: 'pipe' });
    return 0;
  } catch (e) { return e.status == null ? -1 : e.status; }
}

const fixedNow = () => '2026-06-06T08:00:00.000Z';

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-anchor-'));
  const receiptsPath = path.join(dir, 'receipts.jsonl');

  // Run 1: egy workflow-futas, anchor_ref nelkul kiirva
  const run1 = makeRun(null, 'ZONE_INCOMPATIBLE');
  fs.writeFileSync(receiptsPath, run1.leafReceipts.map(r => JSON.stringify(r)).join('\n') + '\n');

  let firstSthRoot = null;

  await check('elso futas: uj STH + minden level lehorgonyozva', async () => {
    const res = await runAnchor({ receiptsPath, privateKeyPem: privPem, backends: ['local'], now: fixedNow });
    assert.ok(res.created, 'nem keletkezett STH');
    assert.strictEqual(res.anchored, 3, `3 levelnek kellett volna lehorgonyozodnia, lett: ${res.anchored}`);
    assert.strictEqual(res.treeSize, 3);
    firstSthRoot = res.sth.root_hash;
    const sths = fs.readFileSync(path.join(dir, 'sth.jsonl'), 'utf8').trim().split('\n');
    assert.strictEqual(sths.length, 1, 'pontosan 1 STH-nak kell lennie');
  });

  await check('verifier elfogadja a lehorgonyzott logot (kilepesi kod 0)', () => {
    assert.strictEqual(runVerifier(dir), 0, 'a verifier nem 0-val tert vissza');
  });

  await check('anchor_ref visszairasa nem rontotta el az alairasokat', () => {
    const receipts = fs.readFileSync(receiptsPath, 'utf8').trim().split('\n').map(JSON.parse);
    for (const r of receipts) {
      assert.ok(r.anchor_ref, 'hianyzik az anchor_ref');
      assert.ok(axr.verifyReceipt(r, pubPem), `ervenytelen alairas: ${r.receipt_id}`);
    }
  });

  await check('idempotencia: uj level nelkul nincs uj STH', async () => {
    const res = await runAnchor({ receiptsPath, privateKeyPem: privPem, backends: ['local'], now: fixedNow });
    assert.ok(!res.created, 'feleslegesen keletkezett STH');
    const sths = fs.readFileSync(path.join(dir, 'sth.jsonl'), 'utf8').trim().split('\n');
    assert.strictEqual(sths.length, 1, 'az STH-szam nem maradhatott 1');
  });

  await check('inkrementalis: uj futas -> uj, lancolt STH + tarto consistency', async () => {
    // Run 2 hozzafuzese (kereszt-futas lanc az elso workflow receipthez)
    const run2 = makeRun(run1.workflowHash, 'DAY_FULL');
    fs.appendFileSync(receiptsPath, run2.leafReceipts.map(r => JSON.stringify(r)).join('\n') + '\n');

    const res = await runAnchor({ receiptsPath, privateKeyPem: privPem, backends: ['local'], now: fixedNow });
    assert.ok(res.created, 'nem keletkezett uj STH a 2. futasra');
    assert.strictEqual(res.treeSize, 6, `6 levelnek kellene lennie, lett: ${res.treeSize}`);
    assert.strictEqual(res.anchored, 3, `csak a 3 uj levelt szabad lehorgonyozni, lett: ${res.anchored}`);

    const sths = fs.readFileSync(path.join(dir, 'sth.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
    assert.strictEqual(sths.length, 2, 'pontosan 2 STH-nak kell lennie');
    // az uj STH az elozore lancol
    assert.strictEqual(sths[1].previous_sth_hash, axr.chainHash(sths[0]), 'az STH-lanc megszakadt');
    // consistency proof 3 -> 6 tart (a kozos core fuggvenyekkel)
    const receipts = fs.readFileSync(receiptsPath, 'utf8').trim().split('\n').map(JSON.parse);
    const leafHashes = receipts.filter(r => ['step', 'workflow', 'identity'].includes(r.receipt_type)).map(axr.leafHash);
    const proof = axr.consistencyProof(3, leafHashes.slice(0, 6));
    assert.ok(axr.verifyConsistency(3, 6, sths[0].root_hash, sths[1].root_hash, proof),
      'a consistency proof 3->6 megbukott');
  });

  await check('verifier tovabbra is elfogadja a ket-STH-s, ket-futasos logot (0)', () => {
    assert.strictEqual(runVerifier(dir), 0, 'a verifier nem 0-val tert vissza a 2. futas utan');
  });

  await check('regi receiptek a sajat (elso) STH-jukra mutatnak', () => {
    const receipts = fs.readFileSync(receiptsPath, 'utf8').trim().split('\n').map(JSON.parse);
    const firstThree = receipts.slice(0, 3);
    for (const r of firstThree) {
      assert.strictEqual(r.anchor_ref.sth_root_hash, firstSthRoot, 'a regi receipt anchor_ref-je atiranyitodott');
      assert.strictEqual(r.anchor_ref.tree_size, 3, 'a regi receipt tree_size-a megvaltozott');
    }
  });

  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (e) {}
  console.log('-'.repeat(72));
  if (process.exitCode === 1) {
    console.log(`EREDMENY: NEM minden teszt zold (${passed} sikeres). Lasd a [HIBA] sorokat.`);
  } else {
    console.log(`EREDMENY: mind a ${passed} teszt zold. A horgonyzo sidecar mukodik.`);
  }
})();
