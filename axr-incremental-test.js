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

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const priv = privateKey.export({ type: 'pkcs8', format: 'pem' });
const pub = publicKey.export({ type: 'spki', format: 'pem' });
const sign = (o) => { const r = { ...o }; delete r.signature; r.signature = core.signReceipt(r, priv); return r; };

function makeRun(prevWf, tag) {
  const wfId = core.uuid();
  let prev = null;
  const steps = [];
  for (let i = 0; i < 2; i++) {
    const s = sign({ axr_version: '0.4', receipt_type: 'step', receipt_id: core.uuid(),
      workflow_receipt_id: wfId, sequence: i + 1,
      step: { node_name: `N${i}`, kind: 'deterministic', deterministic: true, model: null },
      io: { input_hash: core.sha256(`${tag}-in-${i}`), output_hash: core.sha256(`${tag}-out-${i}`), decision: null },
      inputs: [], previous_receipt_hash: prev, anchor_ref: null });
    steps.push(s); prev = core.chainHash(s);
  }
  const wf = sign({ axr_version: '0.4', receipt_type: 'workflow', receipt_id: wfId,
    workflow: { workflow_id: 'wf', trigger_timestamp: tag }, actor: { agent_id: 'a', identity_ref: null },
    request: { input_hash: core.sha256(`${tag}-raw`), customer_ref: core.customerRef('a', 'b', 'c') },
    outcome: { final_status: tag, available: false, decision_summary: tag },
    step_chain: steps.map(s => s.receipt_id), chain_root_hash: core.chainHash(steps[steps.length - 1]),
    previous_receipt_hash: prevWf || null, anchor_ref: null });
  return { leafReceipts: [...steps, wf], wfHash: core.chainHash(wf) };
}

(async () => {
  await check('MMR-gyoker bajtra egyezik a merkleRootFromLeaves-szel (n=1..40)', () => {
    let peaks = [];
    const leaves = [];
    for (let n = 1; n <= 40; n++) {
      const h = core.leafHash({ leaf: n, tag: `node-${n}` });
      leaves.push(h);
      peaks = core.mmrAppend(peaks, h);
      assert.strictEqual(core.mmrRoot(peaks), core.merkleRootFromLeaves(leaves), `n=${n}: MMR != scratch`);
    }
  });

  await check('tobb-futasos inkrementalis horgonyzas: minden STH-gyoker == from-scratch + verifier 0', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-inc-'));
    const rp = path.join(dir, 'receipts.jsonl');
    fs.writeFileSync(rp, '');
    let prevWf = null;
    const allLeaves = [];
    for (let run = 0; run < 5; run++) {
      const r = makeRun(prevWf, `RUN${run}`); prevWf = r.wfHash;
      fs.appendFileSync(rp, r.leafReceipts.map(x => JSON.stringify(x)).join('\n') + '\n');
      for (const lr of r.leafReceipts) allLeaves.push(core.leafHash(lr));
      const res = await runAnchor({ receiptsPath: rp, privateKeyPem: priv, backends: ['local'],
        now: () => `2026-06-08T00:0${run}:00.000Z` });
      assert.ok(res.created, `run ${run}: nem keletkezett STH`);
      assert.strictEqual(res.sth.root_hash, core.merkleRootFromLeaves(allLeaves), `run ${run}: STH-gyoker != from-scratch`);
      const st = JSON.parse(fs.readFileSync(path.join(dir, 'anchor-state.json'), 'utf8'));
      assert.strictEqual(st.leaf_count, allLeaves.length, `run ${run}: rossz leaf_count a cache-ben`);
    }
    const kp = path.join(dir, 'public-key.pem'); fs.writeFileSync(kp, pub);
    let code; try {
      execFileSync('node', [path.join(__dirname, 'axr-verify.js'), rp, kp,
        path.join(dir, 'sth.jsonl'), path.join(dir, 'anchors.jsonl')], { stdio: 'pipe' }); code = 0;
    } catch (e) { code = e.status; }
    assert.strictEqual(code, 0, 'a verifier elutasitotta az inkrementalisan horgonyzott logot');
    fs.rmSync(dir, { recursive: true, force: true });
  });

  await check('serult/torolt cache -> a sidecar nullarol ujraepit, helyes eredmennyel', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-inc2-'));
    const rp = path.join(dir, 'receipts.jsonl');
    const r1 = makeRun(null, 'A');
    fs.writeFileSync(rp, r1.leafReceipts.map(x => JSON.stringify(x)).join('\n') + '\n');
    await runAnchor({ receiptsPath: rp, privateKeyPem: priv, backends: ['local'], now: () => 't1' });
    fs.writeFileSync(path.join(dir, 'anchor-state.json'), '{"leaf_count": 999, "leaf_hashes": [], "peaks": []}');
    const r2 = makeRun(r1.wfHash, 'B');
    fs.appendFileSync(rp, r2.leafReceipts.map(x => JSON.stringify(x)).join('\n') + '\n');
    const res = await runAnchor({ receiptsPath: rp, privateKeyPem: priv, backends: ['local'], now: () => 't2' });
    const allLeaves = [...r1.leafReceipts, ...r2.leafReceipts].map(core.leafHash);
    assert.strictEqual(res.sth.root_hash, core.merkleRootFromLeaves(allLeaves), 'a serult cache utan a gyoker hibas');
    const st = JSON.parse(fs.readFileSync(path.join(dir, 'anchor-state.json'), 'utf8'));
    assert.strictEqual(st.leaf_count, allLeaves.length, 'a cache nem allt helyre');
    fs.rmSync(dir, { recursive: true, force: true });
  });

  console.log('-'.repeat(72));
  if (process.exitCode === 1) {
    console.log(`EREDMENY: NEM minden teszt zold (${passed} sikeres).`);
  } else {
    console.log(`EREDMENY: mind a ${passed} teszt zold. Az inkrementalis Merkle azonos eredmenyt ad, gyorsabban.`);
  }
})();
