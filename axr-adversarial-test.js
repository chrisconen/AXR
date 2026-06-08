// ═══════════════════════════════════════════════════════════════════════════════
// AXR - Adverszariális tesztsor: "tamper-evident" RENDSZERSZINTU bizonyitasa
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-adversarial-test.js
//
// A per-feature tesztek azt mutatjak, hogy egy adott tamper elbukik. Ez a suite
// erosebb allitast bizonyit: epitunk EGY valid, lehorgonyzott, generativ+redactable
// lepest is tartalmazo logot, majd SOKFELEKEPP megmasitjuk, es elvarjuk, hogy a
// kulonallo verifier MINDET elutasitsa (kilepesi kod 1). A valtozatlan log
// kontrollként atmegy (0).
//
// Megj.: a verifier a lepeseket SEQUENCE szerint rendezi, nem fajlsorrend szerint
// (a sequence + step_chain a mervado). Ezert a puszta sorcsere NEM tamadas - ezt
// nem is teszteljuk elutasitaskent; helyette a sequence/lanc/step_chain tenyleges
// serteseit.
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

let passed = 0, failed = 0;
function check(name, fn) {
  return Promise.resolve().then(fn)
    .then(() => { passed++; console.log(`  ok  - ${name}`); })
    .catch(e => { failed++; console.log(`  HIBA - ${name}\n        ${e.message}`); process.exitCode = 1; });
}

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const priv = privateKey.export({ type: 'pkcs8', format: 'pem' });
const pub = publicKey.export({ type: 'spki', format: 'pem' });
const sign = (o) => { const r = { ...o }; delete r.signature; r.signature = core.signReceipt(r, priv); return r; };
const resign = (r) => { delete r.signature; r.signature = core.signReceipt(r, priv); return r; };
const readJsonl = (p) => fs.readFileSync(p, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);

// ── Egy valid, ket-futasos, lehorgonyzott log felepitese ───────────────────────
// run1: Normalize (det) + Intent Classifier (generativ + redactable) + Brain
//       (det, decision, inputs=[classifier])  -> 8/9/13 ellenorzesek lefedese
// run2: egy egyszeru lepes + workflow (kereszt-futas lanc)
async function buildBaseLog() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-adv-base-'));
  const rp = path.join(dir, 'receipts.jsonl');
  const now1 = () => '2026-06-08T00:00:00.000Z';
  const now2 = () => '2026-06-08T00:01:00.000Z';

  // run1
  const wf1Id = core.uuid();
  let prev = null;
  const s1 = sign({ axr_version: '0.4', receipt_type: 'step', receipt_id: core.uuid(),
    workflow_receipt_id: wf1Id, sequence: 1,
    step: { node_name: 'Normalize', node_type: 'n8n-nodes-base.code', kind: 'deterministic', deterministic: true, model: null },
    io: { input_hash: core.sha256('n-in'), output_hash: core.sha256('n-out'), input_summary: {}, decision: null },
    inputs: [], approval: null, previous_receipt_hash: prev, anchor_ref: null });
  prev = core.chainHash(s1);

  const red = core.buildRedactable([{ path: 'generation.prompt', value: [{ role: 'user', content: 'PII: Teszt Elek +3630' }] }]);
  const clsId = core.uuid();
  let cls = { axr_version: '0.4', receipt_type: 'step', receipt_id: clsId,
    workflow_receipt_id: wf1Id, sequence: 2,
    step: { node_name: 'Intent Classifier', node_type: 'n8n-nodes-base.openAi', kind: 'generative', deterministic: false,
            model: { provider: 'anthropic', id: 'claude-sonnet-4-5', fingerprint: null } },
    generation: { params: { temperature: 0 }, prompt_hash: red.redactable.fields[0].leaf_hash, tools_hash: null,
                  completion_hash: core.sha256('completion'), prompt_ref: 'redactable://generation.prompt', completion_ref: null,
                  usage: { input_tokens: 10, output_tokens: 2 }, finish_reason: 'stop',
                  reproducibility: { level: 'best_effort', deterministic_settings: true, notes: '' } },
    io: { input_hash: core.sha256('c-in'), output_hash: core.sha256('c-out'), input_summary: {}, decision: null },
    inputs: [], approval: null, previous_receipt_hash: prev, anchor_ref: null, redactable_root: red.redactable_root };
  cls.redactable = red.redactable;
  cls = sign(cls);
  prev = core.chainHash(cls);

  const brain = sign({ axr_version: '0.4', receipt_type: 'step', receipt_id: core.uuid(),
    workflow_receipt_id: wf1Id, sequence: 3,
    step: { node_name: 'The Brain (Logic)', node_type: 'n8n-nodes-base.code', kind: 'deterministic', deterministic: true, model: null },
    io: { input_hash: core.sha256('b-in'), output_hash: core.sha256('b-out'), input_summary: {},
          decision: { status: 'SLOT_AVAILABLE', available: true } },
    inputs: [clsId], approval: null, previous_receipt_hash: prev, anchor_ref: null });

  const steps1 = [s1, cls, brain];
  const wf1 = sign({ axr_version: '0.4', receipt_type: 'workflow', receipt_id: wf1Id,
    workflow: { workflow_id: 'wf', workflow_version: '1', webhook_path: 'p', trigger_timestamp: 't', completion_timestamp: 't' },
    actor: { agent_id: 'a', agent_type: 'n8n-workflow', operator: 'op', on_behalf_of: 'cust', identity_ref: null },
    request: { input_hash: core.sha256('raw1'), customer_ref: core.customerRef('a', 'b', 'c') },
    outcome: { final_status: 'SLOT_AVAILABLE', available: true, decision_summary: 'ok' },
    step_chain: steps1.map(s => s.receipt_id), chain_root_hash: core.chainHash(brain),
    approval: null, previous_receipt_hash: null, anchor_ref: null });

  fs.writeFileSync(rp, [...steps1, wf1].map(x => JSON.stringify(x)).join('\n') + '\n');
  await runAnchor({ receiptsPath: rp, privateKeyPem: priv, backends: ['local'], now: now1 });

  // run2
  const wf2Id = core.uuid();
  const s2 = sign({ axr_version: '0.4', receipt_type: 'step', receipt_id: core.uuid(),
    workflow_receipt_id: wf2Id, sequence: 1,
    step: { node_name: 'Step2', node_type: 'n8n-nodes-base.code', kind: 'deterministic', deterministic: true, model: null },
    io: { input_hash: core.sha256('2-in'), output_hash: core.sha256('2-out'), input_summary: {}, decision: null },
    inputs: [], approval: null, previous_receipt_hash: null, anchor_ref: null });
  const wf2 = sign({ axr_version: '0.4', receipt_type: 'workflow', receipt_id: wf2Id,
    workflow: { workflow_id: 'wf', workflow_version: '1', webhook_path: 'p', trigger_timestamp: 't2', completion_timestamp: 't2' },
    actor: { agent_id: 'a', agent_type: 'n8n-workflow', operator: 'op', on_behalf_of: 'cust', identity_ref: null },
    request: { input_hash: core.sha256('raw2'), customer_ref: core.customerRef('d', 'e', 'f') },
    outcome: { final_status: 'DAY_FULL', available: false, decision_summary: 'no' },
    step_chain: [s2.receipt_id], chain_root_hash: core.chainHash(s2),
    approval: null, previous_receipt_hash: core.chainHash(wf1), anchor_ref: null });

  fs.appendFileSync(rp, [s2, wf2].map(x => JSON.stringify(x)).join('\n') + '\n');
  await runAnchor({ receiptsPath: rp, privateKeyPem: priv, backends: ['local'], now: now2 });

  return {
    receipts: readJsonl(rp),
    sths: readJsonl(path.join(dir, 'sth.jsonl')),
    anchors: readJsonl(path.join(dir, 'anchors.jsonl'))
  };
}

function writeAndVerify(state) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-adv-'));
  fs.writeFileSync(path.join(dir, 'receipts.jsonl'), state.receipts.map(r => JSON.stringify(r)).join('\n') + '\n');
  fs.writeFileSync(path.join(dir, 'sth.jsonl'), state.sths.map(r => JSON.stringify(r)).join('\n') + '\n');
  fs.writeFileSync(path.join(dir, 'anchors.jsonl'), state.anchors.map(r => JSON.stringify(r)).join('\n') + '\n');
  fs.writeFileSync(path.join(dir, 'public-key.pem'), pub);
  let code, out = '';
  try {
    out = execFileSync('node', [path.join(__dirname, 'axr-verify.js'),
      path.join(dir, 'receipts.jsonl'), path.join(dir, 'public-key.pem'),
      path.join(dir, 'sth.jsonl'), path.join(dir, 'anchors.jsonl')], { encoding: 'utf8' });
    code = 0;
  } catch (e) { code = e.status == null ? -1 : e.status; out = (e.stdout || '').toString(); }
  fs.rmSync(dir, { recursive: true, force: true });
  return { code, out };
}

const clone = (st) => JSON.parse(JSON.stringify(st));
const findStep = (st, name) => st.receipts.find(r => r.step && r.step.node_name === name);
const firstWf = (st) => st.receipts.find(r => r.receipt_type === 'workflow');
const firstAnchored = (st) => st.receipts.find(r => r.anchor_ref && Array.isArray(r.anchor_ref.inclusion_proof));

// ── A tamadas-mátrix: minden mutacionak ELUTASITASBA kell fulladnia ────────────
const MUTATIONS = [
  ['M01 torzs-hamisitas (alairt mezo)', st => { st.receipts[0].io.output_hash = core.sha256('HAMIS'); }],
  ['M02 kozepso lepes torlese (lanc + step_chain)', st => { st.receipts.splice(1, 1); }],
  ['M03 ket receipt alairas-csereje', st => { const t = st.receipts[0].signature; st.receipts[0].signature = st.receipts[1].signature; st.receipts[1].signature = t; }],
  ['M04 utolso STH eltavolitasa (hivatkozott fa eltunik)', st => { st.sths.pop(); }],
  ['M05 inclusion proof elrontasa', st => { firstAnchored(st).anchor_ref.inclusion_proof[0] = 'sha256:' + '0'.repeat(64); }],
  ['M06 anchor_ref.leaf_index hamisitas', st => { const r = firstAnchored(st); r.anchor_ref.leaf_index = (r.anchor_ref.leaf_index + 1) % r.anchor_ref.tree_size; }],
  ['M07 redactable mezo ertek-hamisitasa (commitment)', st => { const r = st.receipts.find(x => x.redactable); r.redactable.fields[0].value = [{ role: 'user', content: 'HAMISITOTT' }]; }],
  ['M08 ujraalairas ROSSZ kulccsal', st => { const wrong = crypto.generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }); const r = st.receipts[0]; delete r.signature; r.signature = core.signReceipt(r, wrong); }],
  ['M09 evidence-graph tores (nem letezo inputs id, re-sign)', st => { const b = findStep(st, 'The Brain (Logic)'); b.inputs = ['00000000-0000-0000-0000-000000000000']; resign(b); }],
  ['M10 chain_root_hash hamisitas (re-sign)', st => { const wf = firstWf(st); wf.chain_root_hash = core.sha256('hamis'); resign(wf); }],
  ['M11 step_chain csonkitas (re-sign)', st => { const wf = st.receipts.find(r => r.receipt_type === 'workflow' && r.step_chain.length > 1); wf.step_chain = wf.step_chain.slice(0, -1); resign(wf); }],
  ['M12 previous_receipt_hash hamisitas (re-sign)', st => { const s = st.receipts.find(r => r.receipt_type === 'step' && r.previous_receipt_hash); s.previous_receipt_hash = core.sha256('hamis'); resign(s); }],
  ['M13 STH root_hash hamisitas (no re-sign)', st => { st.sths[0].root_hash = core.sha256('hamis'); }],
  ['M14 STH previous_sth_hash hamisitas (re-sign)', st => { assert.ok(st.sths.length > 1, 'nincs 2 STH'); st.sths[1].previous_sth_hash = core.sha256('hamis'); resign(st.sths[1]); }],
  ['M15 generativ lepes decision-hamisitasa (re-sign)', st => { const c = findStep(st, 'Intent Classifier'); c.io.decision = { status: 'INJECT' }; resign(c); }]
];

(async () => {
  const base = await buildBaseLog();

  await check('KONTROLL: a valtozatlan log atmegy (kilepesi kod 0)', () => {
    const res = writeAndVerify(base);
    assert.strictEqual(res.code, 0, `a valid log nem 0-val tert vissza:\n${res.out}`);
  });

  let rejected = 0;
  for (const [name, fn] of MUTATIONS) {
    await check(name + ' -> elutasitva (1)', () => {
      const st = clone(base);
      fn(st);
      const res = writeAndVerify(st);
      assert.strictEqual(res.code, 1, `a mutaciot NEM utasitotta el (kod ${res.code}):\n${res.out}`);
      rejected++;
    });
  }

  console.log('-'.repeat(72));
  if (process.exitCode === 1) {
    console.log(`EREDMENY: NEM minden teszt zold (${passed} sikeres, ${failed} bukott).`);
  } else {
    console.log(`EREDMENY: mind a ${passed} teszt zold. ${rejected}/${MUTATIONS.length} tamadas-tipus elutasitva, a valid log atmegy.`);
  }
})();
