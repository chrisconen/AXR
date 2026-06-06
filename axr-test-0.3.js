// ═══════════════════════════════════════════════════════════════════════════════
// AXR 0.3 Stage A - teszt-vektorok es integracios teszt
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-test-0.3.js
//
// Mit ellenoriz:
//   A) Merkle (RFC 6962) primitivek a core-ban:
//      - determinisztikus gyoker, ismert kis meretekre
//      - inclusion proof round-trip MINDEN indexre, n=1..17
//      - consistency proof round-trip MINDEN (m,n) parra, valamint tamper-bukas
//   B) Verzio-fuggo alairas: 0.3-nal az anchor_ref kesobbi hozzaadasa NEM rontja
//      el az alairast; 0.2-nel nincs ilyen mezo-kihagyas
//   C) Vegpontok kozti integracio: egy szintetikus 0.3 log (receipt + STH + anchor)
//      felepitese, majd a kulonallo axr-verify.js futtatasa rajta
//        - ep log -> kilepesi kod 0
//        - megmasitott receipt-torzs -> kilepesi kod 1 (alairas bukik)
//        - megmasitott inclusion proof -> kilepesi kod 1 (10. ellenorzes bukik)
//
// Nulla kulso fuggoseg - csak a Node beepitett moduljai.
// Kilepesi kod: 0 ha minden teszt zold, 1 ha barmi megbukik.
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

// ── Ed25519 kulcspar a teszthez ────────────────────────────────────────────────
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
const pubPem  = publicKey.export({ type: 'spki', format: 'pem' });

console.log('A) Merkle (RFC 6962) primitivek');

// "Level" objektumok - a leafHash strippeli az anchor_ref-et es kanonizal,
// igy barmilyen objektum hasznalhato levelnek.
const makeLeaves = (n) => Array.from({ length: n }, (_, i) => ({ leaf: i, tag: `node-${i}` }));

check('merkleRoot determinisztikus es meret-fuggo', () => {
  const a = core.merkleRoot(makeLeaves(5));
  const b = core.merkleRoot(makeLeaves(5));
  assert.strictEqual(a, b, 'ugyanazon bemenet ket gyokere elter');
  assert.notStrictEqual(core.merkleRoot(makeLeaves(4)), a, '4 es 5 level gyokere nem terhet el? de igen');
  assert.match(a, /^sha256:[0-9a-f]{64}$/);
});

check('egy level: a gyoker maga a level-hash', () => {
  const leaves = makeLeaves(1);
  assert.strictEqual(core.merkleRoot(leaves), core.leafHash(leaves[0]));
});

check('inclusion proof round-trip minden indexre, n=1..17', () => {
  for (let n = 1; n <= 17; n++) {
    const leaves = makeLeaves(n);
    const root = core.merkleRoot(leaves);
    const leafHashes = leaves.map(core.leafHash);
    for (let i = 0; i < n; i++) {
      const proof = core.inclusionProof(i, leafHashes);
      const ok = core.verifyInclusion(core.leafHash(leaves[i]), i, n, proof, root);
      assert.ok(ok, `inclusion proof bukott: n=${n}, i=${i}`);
    }
  }
});

check('inclusion proof tamper -> bukik', () => {
  const n = 9, leaves = makeLeaves(n);
  const root = core.merkleRoot(leaves);
  const leafHashes = leaves.map(core.leafHash);
  const proof = core.inclusionProof(3, leafHashes);
  // egy bizonyitek-elem elrontasa
  const bad = proof.slice();
  bad[0] = 'sha256:' + '0'.repeat(64);
  assert.ok(!core.verifyInclusion(core.leafHash(leaves[3]), 3, n, bad, root), 'rontott proof-ot elfogadott');
  // rossz level
  assert.ok(!core.verifyInclusion(core.leafHash({ leaf: 999 }), 3, n, proof, root), 'rossz levelet elfogadott');
});

check('consistency proof round-trip minden (m,n) parra, n=1..16', () => {
  for (let n = 1; n <= 16; n++) {
    const leaves = makeLeaves(n);
    const leafHashes = leaves.map(core.leafHash);
    const fullRoot = core.merkleRootFromLeaves(leafHashes);
    for (let m = 1; m <= n; m++) {
      const oldRoot = core.merkleRootFromLeaves(leafHashes.slice(0, m));
      const proof = core.consistencyProof(m, leafHashes);
      const ok = core.verifyConsistency(m, n, oldRoot, fullRoot, proof);
      assert.ok(ok, `consistency proof bukott: m=${m}, n=${n}`);
    }
  }
});

check('consistency proof tamper -> bukik (atiras/fork detektalas)', () => {
  const n = 11, leaves = makeLeaves(n);
  const leafHashes = leaves.map(core.leafHash);
  const fullRoot = core.merkleRootFromLeaves(leafHashes);
  const m = 6;
  const oldRoot = core.merkleRootFromLeaves(leafHashes.slice(0, m));
  const proof = core.consistencyProof(m, leafHashes);
  // hamis "regi" gyoker (mintha a multat atirtak volna)
  const fakeOld = core.merkleRootFromLeaves(makeLeaves(m).map((x, i) => core.leafHash({ leaf: i, tag: 'HAMIS' })));
  assert.ok(!core.verifyConsistency(m, n, fakeOld, fullRoot, proof), 'hamis regi gyokeret elfogadott');
  // rontott proof
  const bad = proof.slice(); bad[0] = 'sha256:' + 'f'.repeat(64);
  assert.ok(!core.verifyConsistency(m, n, oldRoot, fullRoot, bad), 'rontott consistency proof-ot elfogadott');
});

console.log('B) Verzio-fuggo alairas (anchor_ref kihagyas 0.3-nal)');

check('0.3: anchor_ref kesobbi hozzaadasa NEM rontja el az alairast', () => {
  const r = {
    axr_version: '0.3', receipt_type: 'step', receipt_id: core.uuid(),
    workflow_receipt_id: 'wf', sequence: 1, io: { input_hash: core.sha256('x'), output_hash: core.sha256('y') },
    previous_receipt_hash: null, anchor_ref: null
  };
  r.signature = core.signReceipt(r, privPem);
  assert.ok(core.verifyReceipt(r, pubPem), 'alapeset: ervenyes alairas');
  // horgonyzas utan: anchor_ref kitoltese
  r.anchor_ref = { sth_root_hash: core.sha256('root'), tree_size: 1, leaf_index: 0, inclusion_proof: [], backends: ['rekor'] };
  assert.ok(core.verifyReceipt(r, pubPem), 'anchor_ref hozzaadasa utan is ervenyesnek kell maradnia');
});

check('0.3: a TORZS megmasitasa elrontja az alairast', () => {
  const r = {
    axr_version: '0.3', receipt_type: 'step', receipt_id: core.uuid(),
    workflow_receipt_id: 'wf', sequence: 1, io: { input_hash: core.sha256('x'), output_hash: core.sha256('y') },
    previous_receipt_hash: null, anchor_ref: null
  };
  r.signature = core.signReceipt(r, privPem);
  r.io.output_hash = core.sha256('MEGMASITVA');
  assert.ok(!core.verifyReceipt(r, pubPem), 'megmasitott torzset elfogadott');
});

console.log('C) Vegpontok kozti integracio (verifier futtatas szintetikus logon)');

// ── Szintetikus 0.3 log felepitese ─────────────────────────────────────────────
function buildSignedReceipt(obj) {
  const r = { ...obj };
  delete r.signature;
  r.signature = core.signReceipt(r, privPem);
  return r;
}

function buildLog() {
  const wfId = core.uuid();
  const genId = core.uuid();
  // 4 lepes (a 3. generativ) + 1 workflow receipt, append-sorrendben
  const steps = [];
  const stepDefs = [
    { name: 'Normalize Payload', kind: 'deterministic', decision: null },
    { name: 'Check Day Schedule', kind: 'deterministic', decision: null },
    { name: 'Intent Classifier', kind: 'generative', decision: null, id: genId },
    { name: 'The Brain (Logic)', kind: 'deterministic',
      decision: { status: 'ZONE_INCOMPATIBLE', available: false, reason: 'DISTANCE_TOO_FAR' },
      inputs: [genId] }
  ];
  let prev = null;
  stepDefs.forEach((d, i) => {
    const base = {
      axr_version: '0.3', receipt_type: 'step', receipt_id: d.id || core.uuid(),
      workflow_receipt_id: wfId, sequence: i + 1, timestamp: '2026-06-06T08:00:00.000Z',
      step: { node_name: d.name, node_type: 'n8n-nodes-base.code', kind: d.kind,
              deterministic: d.kind === 'deterministic', model: null },
      io: { input_hash: core.sha256(`in-${i}`), output_hash: core.sha256(`out-${i}`),
            input_summary: { idx: i }, decision: d.decision },
      inputs: d.inputs || [], approval: null, previous_receipt_hash: prev, anchor_ref: null
    };
    if (d.kind === 'generative') {
      base.step.model = { provider: 'anthropic', id: 'claude-sonnet-4-5-20250929', fingerprint: null,
                          endpoint: 'https://api.anthropic.com/v1/messages' };
      base.step.deterministic = false;
      base.generation = {
        params: { temperature: 0.0, top_p: 1.0, max_tokens: 512, seed: null, stop: [] },
        prompt_hash: core.sha256(`prompt-${i}`), tools_hash: null, completion_hash: core.sha256(`completion-${i}`),
        prompt_ref: null, completion_ref: null, usage: { input_tokens: 734, output_tokens: 18 },
        finish_reason: 'stop',
        reproducibility: { level: 'best_effort', deterministic_settings: true, notes: 'temp=0' }
      };
      base.io.decision = null;
    }
    const signed = buildSignedReceipt(base);
    steps.push(signed);
    prev = core.chainHash(signed); // 0.3: az anchor_ref kihagyasaval kepzett lanc-hash
  });

  const wfBase = {
    axr_version: '0.3', receipt_type: 'workflow', receipt_id: wfId,
    workflow: { workflow_id: 'eco-clean-geo-cluster-booking-hu', workflow_version: '5.0',
                webhook_path: 'booking-request-hu', trigger_timestamp: '2026-06-06T08:00:00.000Z',
                completion_timestamp: '2026-06-06T08:00:00.456Z' },
    actor: { agent_id: 'eco-clean-booking-hu', agent_type: 'n8n-workflow', operator: 'Conen Digital',
             on_behalf_of: 'ECO Clean HU', identity_ref: null },
    request: { input_hash: core.sha256('raw-body'), customer_ref: core.customerRef('a', 'b', 'c') },
    outcome: { final_status: 'ZONE_INCOMPATIBLE', available: false, decision_summary: 'Elutasitva: ZONE_INCOMPATIBLE' },
    step_chain: steps.map(s => s.receipt_id),
    chain_root_hash: core.chainHash(steps[steps.length - 1]),
    approval: null, previous_receipt_hash: null, anchor_ref: null
  };
  const wf = buildSignedReceipt(wfBase);

  // Append-sorrend: eloszor a lepesek, majd a workflow receipt
  const leafReceipts = [...steps, wf];
  const leafHashes = leafReceipts.map(core.leafHash);

  // Ket STH: az elso az elso 3 levelre, a masodik a teljes (5) fara
  const m = 3, n = leafReceipts.length;
  const sth1Base = {
    axr_version: '0.3', record_type: 'sth', log_id: 'axr:eco-clean-booking-hu:v1',
    tree_size: m, root_hash: core.merkleRootFromLeaves(leafHashes.slice(0, m)),
    timestamp: '2026-06-06T08:00:00.100Z', previous_sth_hash: null
  };
  const sth1 = buildSignedReceipt(sth1Base);
  const sth2Base = {
    axr_version: '0.3', record_type: 'sth', log_id: 'axr:eco-clean-booking-hu:v1',
    tree_size: n, root_hash: core.merkleRootFromLeaves(leafHashes),
    timestamp: '2026-06-06T08:00:00.200Z', previous_sth_hash: core.chainHash(sth1)
  };
  const sth2 = buildSignedReceipt(sth2Base);

  // Minden receipt anchor_ref-je az STH2 (teljes fa) ala mutat
  leafReceipts.forEach((r, i) => {
    r.anchor_ref = {
      sth_root_hash: sth2.root_hash, tree_size: n, leaf_index: i,
      inclusion_proof: core.inclusionProof(i, leafHashes), backends: ['opentimestamps']
    };
  });

  const anchorRecords = [{
    axr_version: '0.3', record_type: 'anchor', sth_root_hash: sth2.root_hash, tree_size: n,
    backend: 'opentimestamps',
    backend_entry: { ots_proof: 'base64-ots-proof-placeholder', bitcoin_block: null },
    retrieved_at: '2026-06-06T08:00:02.000Z'
  }];

  return { leafReceipts, sths: [sth1, sth2], anchors: anchorRecords };
}

function writeAndVerify(dir, leafReceipts, sths, anchors) {
  const rp = path.join(dir, 'receipts.jsonl');
  const sp = path.join(dir, 'sth.jsonl');
  const ap = path.join(dir, 'anchors.jsonl');
  const kp = path.join(dir, 'public-key.pem');
  fs.writeFileSync(rp, leafReceipts.map(r => JSON.stringify(r)).join('\n') + '\n');
  fs.writeFileSync(sp, sths.map(r => JSON.stringify(r)).join('\n') + '\n');
  fs.writeFileSync(ap, anchors.map(r => JSON.stringify(r)).join('\n') + '\n');
  fs.writeFileSync(kp, pubPem);
  try {
    execFileSync('node', [path.join(__dirname, 'axr-verify.js'), rp, kp, sp, ap], { stdio: 'pipe' });
    return 0;
  } catch (e) {
    return e.status == null ? -1 : e.status;
  }
}

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-test-'));

check('ep 0.3 log -> verifier kilepesi kod 0', () => {
  const { leafReceipts, sths, anchors } = buildLog();
  const code = writeAndVerify(tmp, leafReceipts, sths, anchors);
  assert.strictEqual(code, 0, `ep logra a verifier ${code} kodot adott (0 helyett)`);
});

check('megmasitott receipt-torzs -> verifier kilepesi kod 1', () => {
  const { leafReceipts, sths, anchors } = buildLog();
  // a Brain dontesi okanak atirasa az alairas utan
  const brain = leafReceipts.find(r => r.step && r.step.node_name === 'The Brain (Logic)');
  brain.io.decision.reason = 'HAMISITOTT_OK';
  const code = writeAndVerify(tmp, leafReceipts, sths, anchors);
  assert.strictEqual(code, 1, `megmasitott torzsre a verifier ${code} kodot adott (1 helyett)`);
});

check('megmasitott inclusion proof -> verifier kilepesi kod 1', () => {
  const { leafReceipts, sths, anchors } = buildLog();
  // egy receipt inclusion proof-janak elrontasa (a torzs es az alairas erintetlen)
  leafReceipts[1].anchor_ref.inclusion_proof[0] = 'sha256:' + '0'.repeat(64);
  const code = writeAndVerify(tmp, leafReceipts, sths, anchors);
  assert.strictEqual(code, 1, `megmasitott inclusion proof-ra a verifier ${code} kodot adott (1 helyett)`);
});

check('torolt lepes (lanc-szakadas) -> verifier kilepesi kod 1', () => {
  const { leafReceipts, sths, anchors } = buildLog();
  // a 2. lepes torlese a kozeprol
  const trimmed = leafReceipts.filter((r, i) => i !== 1);
  const code = writeAndVerify(tmp, trimmed, sths, anchors);
  assert.strictEqual(code, 1, `torolt lepesre a verifier ${code} kodot adott (1 helyett)`);
});

// ── Osszegzes ──────────────────────────────────────────────────────────────────
try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (e) {}
console.log('-'.repeat(72));
if (process.exitCode === 1) {
  console.log(`EREDMENY: NEM minden teszt zold (${passed} sikeres). Lasd a [HIBA] sorokat.`);
} else {
  console.log(`EREDMENY: mind a ${passed} teszt zold. A 0.3 Merkle + horgonyzas verifikalas mukodik.`);
}
