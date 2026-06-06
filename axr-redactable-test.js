// ═══════════════════════════════════════════════════════════════════════════════
// AXR 0.4 (prototipus) - Redactable receipts: GDPR torles vs append-only
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-redactable-test.js
//
// A forgatokonyv: egy generativ lepes MEGORIZI a prompt + completion cleartextet
// (audit/evidencia celbol), de REDACTABLE modon - mezo-szintu sozott Merkle-commit
// alatt. A receiptet alairjuk es lehorgonyozzuk. Kesobb egy GDPR torlesi keresre a
// prompt cleartextjet TOROLJUK. A kulcs allitas: a torles utan
//   - az alairas tovabbra is ervenyes,
//   - a lanc-hash valtozatlan,
//   - a (lehorgonyzott) level-hash valtozatlan -> az inclusion proof tovabb el,
//   - a commitment ellenorizheto,
//   - a szemelyes adat viszont VALOBAN eltunt (nem brute-forcolhato a so miatt).
//
// Mit ellenoriz:
//   1. ep redactable receipt -> verifier 0; verifyRedactable ok
//   2. teljes pipeline: sidecar horgonyzas + verifier (anchors) -> 0
//   3. REDAKCIO: a prompt torlese utan a cleartext eltunt, az alairas ep,
//      a level-hash valtozatlan, es a verifier (anchors) tovabbra is 0
//   4. NEGATIV: egy jelenlevo mezo erteke-modositasa (a leaf_hash valtozatlanul) ->
//      a commitment elbukik (13. ellenorzes) -> verifier 1
//   5. NEGATIV: a redactable_root utolagos atirasa -> alairas bukik -> verifier 1
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

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
const pubPem = publicKey.export({ type: 'spki', format: 'pem' });

// PII a promptban - ennek nyom nelkul kell eltunnie a redakcio utan
const PII = 'Kovacs Janos, +36301234567, kovacs.janos@example.com';

function buildRedactableLog() {
  const wfId = core.uuid();
  const promptMessages = [
    { role: 'system', content: 'Osztalyozd a beerkezo uzenetet.' },
    { role: 'user', content: `Foglalas: ${PII}, jovo kedd 14:00` }
  ];
  const completion = { intent: 'BOOKING_REQUEST', confidence: 0.97 };

  // mezo-szintu sozott commit a prompt + completion cleartextre
  const red = core.buildRedactable([
    { path: 'generation.prompt', value: promptMessages },
    { path: 'generation.completion', value: completion }
  ]);
  const leafOf = (p) => red.redactable.fields.find(f => f.path === p).leaf_hash;

  const stepBody = {
    axr_version: '0.4', receipt_type: 'step', receipt_id: core.uuid(),
    workflow_receipt_id: wfId, sequence: 1, timestamp: '2026-06-06T08:00:00.000Z',
    step: { node_name: 'Intent Classifier', node_type: 'n8n-nodes-base.openAi',
            kind: 'generative', deterministic: false,
            model: { provider: 'anthropic', id: 'claude-sonnet-4-5-20250929', fingerprint: null,
                     endpoint: 'https://api.anthropic.com/v1/messages' } },
    generation: {
      params: { temperature: 0.0, top_p: 1.0, max_tokens: 256, seed: null, stop: [] },
      // a tartalom-hash MAGA a sozott redactable commitment leaf-e: igy nincs
      // kulon sotlan (brute-forcolhato) tartalom-hash a receiptben
      prompt_hash: leafOf('generation.prompt'),
      tools_hash: null,
      completion_hash: leafOf('generation.completion'),
      prompt_ref: 'redactable://generation.prompt',
      completion_ref: 'redactable://generation.completion',
      usage: { input_tokens: 734, output_tokens: 18 }, finish_reason: 'stop',
      reproducibility: { level: 'best_effort', deterministic_settings: true, notes: 'temp=0' }
    },
    io: { input_hash: core.sha256('classifier-input'), output_hash: core.sha256('classifier-output'),
          input_summary: { channel: 'webform', lang: 'hu' }, decision: null },
    inputs: [], approval: null, previous_receipt_hash: null, anchor_ref: null,
    redactable_root: red.redactable_root
  };
  stepBody.redactable = red.redactable;
  stepBody.signature = core.signReceipt(stepBody, privPem);

  const wfBody = {
    axr_version: '0.4', receipt_type: 'workflow', receipt_id: wfId,
    workflow: { workflow_id: 'eco-clean-geo-cluster-booking-hu', workflow_version: '5.1',
                webhook_path: 'booking-request-hu', trigger_timestamp: '2026-06-06T08:00:00.000Z',
                completion_timestamp: '2026-06-06T08:00:00.456Z' },
    actor: { agent_id: 'eco-clean-booking-hu', agent_type: 'n8n-workflow', operator: 'Conen Digital',
             on_behalf_of: 'ECO Clean HU', identity_ref: null },
    request: { input_hash: core.sha256('raw'), customer_ref: core.customerRef('a', 'b', 'c') },
    outcome: { final_status: 'SLOT_AVAILABLE', available: true, decision_summary: 'ok' },
    step_chain: [stepBody.receipt_id], chain_root_hash: core.chainHash(stepBody),
    approval: null, previous_receipt_hash: null, anchor_ref: null
  };
  wfBody.signature = core.signReceipt(wfBody, privPem);
  return { step: stepBody, workflow: wfBody };
}

function writeLog(dir, receipts) {
  const rp = path.join(dir, 'receipts.jsonl');
  fs.writeFileSync(rp, receipts.map(r => JSON.stringify(r)).join('\n') + '\n');
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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-red-'));
  const log = buildRedactableLog();

  await check('ep redactable receipt: verifier 0 + verifyRedactable ok', () => {
    writeLog(dir, [log.step, log.workflow]);
    assert.ok(core.verifyReceipt(log.step, pubPem), 'a step alairasa ervenytelen');
    const vr = core.verifyRedactable(log.step);
    assert.ok(vr.ok, 'verifyRedactable nem ok: ' + JSON.stringify(vr.problems));
    assert.strictEqual(runVerifier(dir, false), 0, 'a verifier nem 0-val tert vissza');
  });

  await check('teljes pipeline: sidecar horgonyzas + verifier (anchors) -> 0', async () => {
    const rp = path.join(dir, 'receipts.jsonl');
    const res = await runAnchor({ receiptsPath: rp, privateKeyPem: privPem, backends: ['local'],
      now: () => '2026-06-06T08:00:01.000Z' });
    assert.ok(res.created && res.anchored === 2, `2 levelt kellett horgonyozni, lett: ${res.anchored}`);
    assert.strictEqual(runVerifier(dir, true), 0, 'a verifier (anchors) nem 0-val tert vissza');
  });

  await check('REDAKCIO: a prompt torlese utan minden ep, a PII eltunt', () => {
    const rp = path.join(dir, 'receipts.jsonl');
    const receipts = fs.readFileSync(rp, 'utf8').trim().split('\n').map(JSON.parse);
    const idx = receipts.findIndex(r => r.receipt_type === 'step');
    const before = receipts[idx];

    // level-hash a redakcio ELOTT (a lehorgonyzott bizonyitek alapja)
    const leafBefore = core.leafHash(before);

    // GDPR torles: a prompt mezo cleartextjenek eldobasa
    const after = core.redactField(before, 'generation.prompt');

    // a PII nyom nelkul eltunt
    assert.ok(!JSON.stringify(after).includes('Kovacs'), 'a PII MEGMARADT a redakcio utan!');
    const promptField = after.redactable.fields.find(f => f.path === 'generation.prompt');
    assert.strictEqual(promptField.value, undefined, 'a prompt value-ja megmaradt');
    assert.strictEqual(promptField.salt, undefined, 'a prompt salt-ja megmaradt');
    assert.strictEqual(promptField.redacted, true, 'a mezo nincs redacted-kent jelolve');

    // az alairas ep marad (a redactable detail kimarad az alairasbol)
    assert.ok(core.verifyReceipt(after, pubPem), 'az alairas eltort a redakcio utan!');
    // a level-hash valtozatlan -> a mar lehorgonyzott inclusion proof tovabb el
    assert.strictEqual(core.leafHash(after), leafBefore, 'a level-hash megvaltozott - eltorne az inclusion proof!');
    // a completion (nem torolt) tovabbra is ellenorizheto, a commitment all
    const vr = core.verifyRedactable(after);
    assert.ok(vr.ok, 'verifyRedactable nem ok a redakcio utan: ' + JSON.stringify(vr.problems));

    // a redaktalt log lemezre irva, anchorokkal egyutt tovabbra is verifikal
    receipts[idx] = after;
    fs.writeFileSync(rp, receipts.map(r => JSON.stringify(r)).join('\n') + '\n');
    assert.strictEqual(runVerifier(dir, true), 0, 'a verifier (anchors) nem 0-val tert vissza a redakcio utan');
  });

  await check('NEGATIV: jelenlevo mezo ertek-hamisitasa -> verifier 1 (13. ellenorzes)', () => {
    const dir2 = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-red-neg1-'));
    const l = buildRedactableLog();
    // a completion ertekenek atirasa, a leaf_hash valtozatlanul (az alairast NEM piszkaljuk)
    const f = l.step.redactable.fields.find(x => x.path === 'generation.completion');
    f.value = { intent: 'HAMISITOTT', confidence: 0.01 };
    writeLog(dir2, [l.step, l.workflow]);
    assert.ok(core.verifyReceipt(l.step, pubPem), 'az alairasnak ervenyesnek kell maradnia (a detail nincs alairva)');
    assert.strictEqual(runVerifier(dir2, false), 1, 'a commitment-serulest a verifier nem fogta el');
    fs.rmSync(dir2, { recursive: true, force: true });
  });

  await check('NEGATIV: redactable_root utolagos atirasa -> alairas bukik -> verifier 1', () => {
    const dir3 = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-red-neg2-'));
    const l = buildRedactableLog();
    l.step.redactable_root = core.sha256('hamis-gyoker'); // a root ALAIRT -> bukik
    writeLog(dir3, [l.step, l.workflow]);
    assert.strictEqual(runVerifier(dir3, false), 1, 'az atirt redactable_root-ot a verifier nem fogta el');
    fs.rmSync(dir3, { recursive: true, force: true });
  });

  fs.rmSync(dir, { recursive: true, force: true });
  console.log('-'.repeat(72));
  if (process.exitCode === 1) {
    console.log(`EREDMENY: NEM minden teszt zold (${passed} sikeres). Lasd a [HIBA] sorokat.`);
  } else {
    console.log(`EREDMENY: mind a ${passed} teszt zold. A redactable receipts (GDPR torles vs append-only) mukodik.`);
  }
})();
