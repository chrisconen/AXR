// ═══════════════════════════════════════════════════════════════════════════════
// AXR 0.3 Stage C - generativ lepes end-to-end
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-generative-test.js
//
// Egy realisztikus workflow: egy LLM-alapu Intent Classifier (generativ lepes),
// majd a determinisztikus Brain, ami a klasszifikator kimenetet FOGYASZTJA. A
// generator (generateReceiptsV3) ebbol egy generativ + egy determinisztikus
// step-receiptet keszit, a Brain inputs[] mezojeben a klasszifikator receipt_id-
// javal (evidence-graph). Vegig: generator -> sidecar (horgonyzas) -> verifier
// -> monitor.
//
// Mit ellenoriz:
//   1. a generativ receipt jol formalt: kind=generative, generation blokk
//      (prompt/completion hash), model.id/provider, io.decision=null
//   2. evidence-graph: a Brain inputs[]-e a klasszifikator receipt_id-jara mutat
//   3. a kulonallo verifier elfogadja a (lehorgonyzott) logot -> 0
//   4. a monitor elfogadja a generativ-lepest tartalmazo log STH-jat
//   5. NEGATIV: a completion-hash utolagos atirasa -> alairas bukik (verifier 1)
//   6. NEGATIV: tort evidence-graph (nem letezo inputs id) -> verifier 1
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
const { generateReceiptsV3 } = require('./axr-generator');
const { runAnchor } = require('./axr-anchor');
const { pollMonitor } = require('./axr-monitor');

let passed = 0;
async function check(name, fn) {
  try { await fn(); passed++; console.log(`  ok  - ${name}`); }
  catch (e) { console.log(`  HIBA - ${name}\n        ${e.message}`); process.exitCode = 1; }
}

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
const pubPem = publicKey.export({ type: 'spki', format: 'pem' });

// ── A workflow node-kimenetei a markerekkel (ahogy az n8n node-ok hagynak) ──────
// Intent Classifier: egy LLM hivas; a kimenete hordozza a __axr_input-ot ES a
// __axr_gen-t (a modell-hivas teljes evidenciaja).
function classifierOutput() {
  return [{
    intent: 'BOOKING_REQUEST',
    confidence: 0.97,
    __axr_input: { channel: 'webform', lang: 'hu', text: 'Szeretnek idopontot foglalni jovo hetre' },
    __axr_gen: {
      model: { provider: 'anthropic', id: 'claude-sonnet-4-5-20250929', fingerprint: null,
               endpoint: 'https://api.anthropic.com/v1/messages' },
      params: { temperature: 0.0, top_p: 1.0, max_tokens: 256, seed: null, stop: [] },
      prompt: [
        { role: 'system', content: 'Osztalyozd a beerkezo uzenetet: BOOKING_REQUEST, QUESTION, OTHER.' },
        { role: 'user', content: 'Szeretnek idopontot foglalni jovo hetre' }
      ],
      tools: null,
      completion: { intent: 'BOOKING_REQUEST', confidence: 0.97 },
      usage: { input_tokens: 734, output_tokens: 18 },
      finish_reason: 'stop',
      reproducibility: { level: 'best_effort', deterministic_settings: true,
                         notes: 'temperature=0 csokkenti a szorast, de nem garantal bit-azonos kimenetet' }
    }
  }];
}
// Brain: determinisztikus dontes, a klasszifikator kimenetet fogyasztja.
function brainOutput() {
  return [{
    status: 'SLOT_AVAILABLE', available: true, cluster: { id: 'BUDAPEST', country: 'HU' },
    slot: { startTime: '2026-06-15T14:00', endTime: '2026-06-15T15:25' },
    __axr_input: { intent: 'BOOKING_REQUEST', date: '2026-06-15', duration_minutes: 85 }
  }];
}

function buildCtx() {
  const outputs = { 'Intent Classifier': classifierOutput(), 'The Brain (Logic)': brainOutput() };
  return {
    steps: [
      { node: 'Intent Classifier', type: 'n8n-nodes-base.openAi' },
      { node: 'The Brain (Logic)', type: 'n8n-nodes-base.code', logic_version: '5.0 HU',
        inputsFrom: ['Intent Classifier'], decision: true,
        extractDecision: (o) => ({ status: o.status, available: o.available === true,
          cluster_id: o.cluster ? o.cluster.id : null,
          assigned_slot: o.slot ? `${o.slot.startTime}-${o.slot.endTime}` : null }) }
    ],
    get: (n) => outputs[n] || null,
    rawWebhookBody: { name: 'Teszt Elek', email: 't@example.com', phone: '+3611', text: 'foglalas' },
    prevWorkflowHash: null, privateKeyPem: privPem,
    workflow: { workflow_id: 'eco-clean-geo-cluster-booking-hu', workflow_version: '5.1', webhook_path: 'booking-request-hu' },
    actor: { agent_id: 'eco-clean-booking-hu', agent_type: 'n8n-workflow', operator: 'Conen Digital', on_behalf_of: 'ECO Clean HU' },
    triggerTimestamp: '2026-06-06T08:00:00.000Z', completionTimestamp: '2026-06-06T08:00:00.456Z',
    decisionSummary: 'Slot SLOT_AVAILABLE, zona BUDAPEST'
  };
}

function writeReceipts(dir, gen) {
  const rp = path.join(dir, 'receipts.jsonl');
  const all = [...gen.stepReceipts, gen.workflowReceipt];
  fs.writeFileSync(rp, all.map(r => JSON.stringify(r)).join('\n') + '\n');
  return rp;
}
function runVerifier(dir, withAnchors) {
  const kp = path.join(dir, 'public-key.pem');
  fs.writeFileSync(kp, pubPem);
  const args = [path.join(__dirname, 'axr-verify.js'), path.join(dir, 'receipts.jsonl'), kp];
  if (withAnchors) args.push(path.join(dir, 'sth.jsonl'), path.join(dir, 'anchors.jsonl'));
  try { execFileSync('node', args, { stdio: 'pipe' }); return 0; }
  catch (e) { return e.status == null ? -1 : e.status; }
}

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-gen-'));
  const gen = generateReceiptsV3(buildCtx());

  await check('a generativ receipt jol formalt (kind/generation/model/decision=null)', () => {
    const c = gen.stepReceipts.find(s => s.step.node_name === 'Intent Classifier');
    assert.ok(c, 'nincs klasszifikator receipt');
    assert.strictEqual(c.step.kind, 'generative');
    assert.strictEqual(c.step.deterministic, false);
    assert.strictEqual(c.step.model.provider, 'anthropic');
    assert.ok(c.step.model.id, 'hianyzik a model.id');
    assert.ok(/^sha256:[0-9a-f]{64}$/.test(c.generation.prompt_hash), 'rossz prompt_hash');
    assert.ok(/^sha256:[0-9a-f]{64}$/.test(c.generation.completion_hash), 'rossz completion_hash');
    assert.strictEqual(c.io.decision, null, 'generativ lepesnek decision=null kell');
    assert.strictEqual(c.generation.finish_reason, 'stop');
    assert.strictEqual(gen.warnings.length, 0, 'varatlan figyelmeztetes: ' + JSON.stringify(gen.warnings));
  });

  await check('evidence-graph: a Brain inputs[]-e a klasszifikatorra mutat', () => {
    const c = gen.stepReceipts.find(s => s.step.node_name === 'Intent Classifier');
    const b = gen.stepReceipts.find(s => s.step.node_name === 'The Brain (Logic)');
    assert.ok(b, 'nincs Brain receipt');
    assert.deepStrictEqual(b.inputs, [c.receipt_id], 'a Brain inputs-e nem a klasszifikator receipt_id-ja');
    assert.ok(b.io.decision && b.io.decision.status === 'SLOT_AVAILABLE', 'hianyzik a Brain dontese');
    assert.ok(b.sequence > c.sequence, 'a Brain-nek a klasszifikator UTAN kell jonnie');
  });

  await check('verifier elfogadja a generativ-lepest tartalmazo logot (0)', () => {
    writeReceipts(dir, gen);
    assert.strictEqual(runVerifier(dir, false), 0, 'a verifier nem 0-val tert vissza');
  });

  await check('teljes pipeline: sidecar horgonyzas + verifier (anchors) -> 0', async () => {
    const rp = writeReceipts(dir, gen);
    const res = await runAnchor({ receiptsPath: rp, privateKeyPem: privPem, backends: ['local'],
      now: () => '2026-06-06T08:00:01.000Z' });
    assert.ok(res.created && res.anchored === 3, `3 levelt kellett horgonyozni, lett: ${res.anchored}`);
    assert.strictEqual(runVerifier(dir, true), 0, 'a verifier (anchors) nem 0-val tert vissza');
  });

  await check('monitor elfogadja a generativ log STH-jat', () => {
    const res = pollMonitor({ sthPath: path.join(dir, 'sth.jsonl'), publicKeyPem: pubPem,
      statePath: path.join(dir, 'monitor-state.json'), receiptsPath: path.join(dir, 'receipts.jsonl'),
      now: () => '2026-06-06T08:00:02.000Z' });
    assert.ok(res.ok, 'a monitor sertest jelzett: ' + JSON.stringify(res.violations));
  });

  await check('NEGATIV: completion_hash utolagos atirasa -> verifier 1', () => {
    const dir2 = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-gen-neg1-'));
    const g2 = generateReceiptsV3(buildCtx());
    const c = g2.stepReceipts.find(s => s.step.node_name === 'Intent Classifier');
    c.generation.completion_hash = axr.sha256('HAMISITOTT-VALASZ'); // alairas utani torzs-modositas
    const rp = path.join(dir2, 'receipts.jsonl');
    fs.writeFileSync(rp, [...g2.stepReceipts, g2.workflowReceipt].map(r => JSON.stringify(r)).join('\n') + '\n');
    assert.strictEqual(runVerifier(dir2, false), 1, 'az atirt completion_hash-t a verifier elfogadta');
    fs.rmSync(dir2, { recursive: true, force: true });
  });

  await check('NEGATIV: tort evidence-graph (nem letezo inputs id) -> verifier 1', () => {
    const dir3 = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-gen-neg2-'));
    const g3 = generateReceiptsV3(buildCtx());
    const b = g3.stepReceipts.find(s => s.step.node_name === 'The Brain (Logic)');
    // FONTOS: ujra kell alairni, kulonben az alairas bukna (nem az evidence-graphot tesztelnenk)
    delete b.signature;
    b.inputs = ['00000000-0000-0000-0000-000000000000'];
    b.signature = axr.signReceipt(b, privPem);
    const rp = path.join(dir3, 'receipts.jsonl');
    fs.writeFileSync(rp, [...g3.stepReceipts, g3.workflowReceipt].map(r => JSON.stringify(r)).join('\n') + '\n');
    assert.strictEqual(runVerifier(dir3, false), 1, 'a tort evidence-graphot a verifier elfogadta');
    fs.rmSync(dir3, { recursive: true, force: true });
  });

  fs.rmSync(dir, { recursive: true, force: true });
  console.log('-'.repeat(72));
  if (process.exitCode === 1) {
    console.log(`EREDMENY: NEM minden teszt zold (${passed} sikeres). Lasd a [HIBA] sorokat.`);
  } else {
    console.log(`EREDMENY: mind a ${passed} teszt zold. A generativ lepes end-to-end mukodik.`);
  }
})();
