// ═══════════════════════════════════════════════════════════════════════════════
// AXR - Cross-implementation teszt: JS <-> Python egyezes
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-crossverify-test.js   (python3 szukseges)
//
// A "barki, barmely nyelven ellenorizheti" allitas bizonyitasa:
//   1. KANONIZALAS-PARITAS: egy ertek-battery JS core.canonicalize kimenete
//      BAJTRA megegyezik a fuggetlen Python canonicalize kimenetevel.
//   2. EGYETERTES (valid): a JS es a Python verifier IS elfogadja ugyanazt a
//      lehorgonyzott logot (mindketto kilepesi kod 0).
//   3. EGYETERTES (tamper): mindketto elutasitja ugyanazokat a manipulalt logokat.
//
// Ha nincs python3, a teszt KIHAGYJA magat (nem bukik).
// Kilepesi kod: 0 ha minden zold (vagy skip), 1 ha barmi megbukik.
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

// Interpreter-felderites: python3, majd python (Windowson gyakran csak ez van;
// a Store-fele python3 alias stub, ami 9009-cel bukik). Csak Python 3 fogadhato el.
function findPython() {
  for (const cand of ['python3', 'python']) {
    try {
      const v = execFileSync(cand, ['--version'], { encoding: 'utf8', stdio: 'pipe' });
      if (/^Python 3\./.test(v.trim())) return cand;
    } catch (e) { /* kovetkezo jelolt */ }
  }
  return null;
}
const PYTHON = findPython();

if (!PYTHON) {
  console.log('  SKIP - python3/python (3.x) nem elerheto; a cross-impl teszt kihagyva.');
  console.log('EREDMENY: kihagyva (nincs python3).');
  process.exit(0);
}

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const priv = privateKey.export({ type: 'pkcs8', format: 'pem' });
const pub = publicKey.export({ type: 'spki', format: 'pem' });
const sign = (o) => { const r = { ...o }; delete r.signature; r.signature = core.signReceipt(r, priv); return r; };
const PYDIR = __dirname;

function runPyVerify(dir) {
  const args = [path.join(PYDIR, 'axr_verify.py'), path.join(dir, 'receipts.jsonl'),
    path.join(dir, 'public-key.pem'), path.join(dir, 'sth.jsonl'), path.join(dir, 'anchors.jsonl')];
  try { return { code: 0, out: execFileSync(PYTHON, args, { encoding: 'utf8' }) }; }
  catch (e) { return { code: e.status == null ? -1 : e.status, out: (e.stdout || '').toString() }; }
}
function runJsVerify(dir) {
  const args = [path.join(PYDIR, 'axr-verify.js'), path.join(dir, 'receipts.jsonl'),
    path.join(dir, 'public-key.pem'), path.join(dir, 'sth.jsonl'), path.join(dir, 'anchors.jsonl')];
  try { return { code: 0, out: execFileSync('node', args, { encoding: 'utf8' }) }; }
  catch (e) { return { code: e.status == null ? -1 : e.status, out: (e.stdout || '').toString() }; }
}

// ── Valid, ket-futasos, lehorgonyzott log (generativ + redactable a stresszhez) ─
async function buildLog(dir) {
  const rp = path.join(dir, 'receipts.jsonl');
  const wf1 = core.uuid();
  let prev = null;
  const s1 = sign({ axr_version: '0.4', receipt_type: 'step', receipt_id: core.uuid(), workflow_receipt_id: wf1, sequence: 1,
    step: { node_name: 'Normalize', kind: 'deterministic', deterministic: true, model: null },
    io: { input_hash: core.sha256('n-in'), output_hash: core.sha256('n-out'), decision: null }, inputs: [],
    previous_receipt_hash: prev, anchor_ref: null });
  prev = core.chainHash(s1);
  const red = core.buildRedactable([{ path: 'generation.prompt', value: [{ role: 'user', content: 'PII: Teszt á-é 😀' }] }]);
  const clsId = core.uuid();
  let cls = { axr_version: '0.4', receipt_type: 'step', receipt_id: clsId, workflow_receipt_id: wf1, sequence: 2,
    step: { node_name: 'Intent Classifier', kind: 'generative', deterministic: false, model: { provider: 'anthropic', id: 'claude-sonnet-4-5', fingerprint: null } },
    generation: { params: { temperature: 0.0, top_p: 1.0 }, prompt_hash: red.redactable.fields[0].leaf_hash, tools_hash: null,
      completion_hash: core.sha256('c'), prompt_ref: null, completion_ref: null, usage: { input_tokens: 7, output_tokens: 2 },
      finish_reason: 'stop', reproducibility: { level: 'best_effort', deterministic_settings: true, notes: '' } },
    io: { input_hash: core.sha256('c-in'), output_hash: core.sha256('c-out'), decision: null }, inputs: [],
    previous_receipt_hash: prev, anchor_ref: null, redactable_root: red.redactable_root };
  cls.redactable = red.redactable; cls = sign(cls); prev = core.chainHash(cls);
  const brain = sign({ axr_version: '0.4', receipt_type: 'step', receipt_id: core.uuid(), workflow_receipt_id: wf1, sequence: 3,
    step: { node_name: 'The Brain (Logic)', kind: 'deterministic', deterministic: true, model: null },
    io: { input_hash: core.sha256('b-in'), output_hash: core.sha256('b-out'), decision: { status: 'SLOT_AVAILABLE', available: true } },
    inputs: [clsId], previous_receipt_hash: prev, anchor_ref: null });
  const steps1 = [s1, cls, brain];
  const w1 = sign({ axr_version: '0.4', receipt_type: 'workflow', receipt_id: wf1,
    workflow: { workflow_id: 'wf', trigger_timestamp: 't' }, actor: { agent_id: 'a', identity_ref: null },
    request: { input_hash: core.sha256('raw'), customer_ref: core.customerRef('a', 'b', 'c') },
    outcome: { final_status: 'SLOT_AVAILABLE', available: true, decision_summary: 'ok' },
    step_chain: steps1.map(s => s.receipt_id), chain_root_hash: core.chainHash(brain), previous_receipt_hash: null, anchor_ref: null });
  fs.writeFileSync(rp, [...steps1, w1].map(x => JSON.stringify(x)).join('\n') + '\n');
  await runAnchor({ receiptsPath: rp, privateKeyPem: priv, backends: ['local'], now: () => '2026-06-08T00:00:00.000Z' });

  const wf2 = core.uuid();
  const s2 = sign({ axr_version: '0.4', receipt_type: 'step', receipt_id: core.uuid(), workflow_receipt_id: wf2, sequence: 1,
    step: { node_name: 'Step2', kind: 'deterministic', deterministic: true, model: null },
    io: { input_hash: core.sha256('2-in'), output_hash: core.sha256('2-out'), decision: null }, inputs: [],
    previous_receipt_hash: null, anchor_ref: null });
  const w2 = sign({ axr_version: '0.4', receipt_type: 'workflow', receipt_id: wf2,
    workflow: { workflow_id: 'wf', trigger_timestamp: 't2' }, actor: { agent_id: 'a', identity_ref: null },
    request: { input_hash: core.sha256('raw2'), customer_ref: core.customerRef('d', 'e', 'f') },
    outcome: { final_status: 'DAY_FULL', available: false, decision_summary: 'no' },
    step_chain: [s2.receipt_id], chain_root_hash: core.chainHash(s2), previous_receipt_hash: core.chainHash(w1), anchor_ref: null });
  fs.appendFileSync(rp, [s2, w2].map(x => JSON.stringify(x)).join('\n') + '\n');
  await runAnchor({ receiptsPath: rp, privateKeyPem: priv, backends: ['local'], now: () => '2026-06-08T00:01:00.000Z' });
  fs.writeFileSync(path.join(dir, 'public-key.pem'), pub);
}

(async () => {
  // ── 1. Kanonizalas-paritas JS <-> Python ──────────────────────────────────────
  await check('kanonizalas-paritas: JS core.canonicalize == Python canonicalize (battery)', () => {
    const battery = [
      null, true, false, 0, 1, -1, 1.0, -0, 0.97, -12.5, 100, 123.456, 1e21, 1e-7, 255, 65535,
      '', 'arvizturo tukorfurogep', 'a-e-o-u accents: \u00e1\u00e9\u0151\u0171', '\ud83d\ude00 emoji',
      'tab\tnl\nquote"back\\slash', '/slash',
      [], {}, [3, 1, 2], { b: 1, a: 2 }, { z: { y: 1, x: 2 }, a: [true, null, 'k'] },
      { '\u00e9': 1, z: 2 }, { n: 0.97, k: [1, 2, 3] }
    ];
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-cx-'));
    const vecPath = path.join(dir, 'vectors.jsonl');
    fs.writeFileSync(vecPath, battery.map(v => JSON.stringify({ v: v, c: core.canonicalize(v) })).join('\n') + '\n');
    const driver = path.join(dir, 'drv.py');
    fs.writeFileSync(driver,
      'import sys, json\n' +
      'sys.path.insert(0, ' + JSON.stringify(PYDIR) + ')\n' +
      'import axr_verify as a\n' +
      'bad = 0\n' +
      'for line in open(sys.argv[1], encoding="utf-8"):\n' +
      '    line = line.strip()\n' +
      '    if not line: continue\n' +
      '    rec = json.loads(line)\n' +
      '    got = a.canonicalize(rec["v"])\n' +
      '    if got != rec["c"]:\n' +
      '        bad += 1; print("ELTER: py=%r js=%r" % (got, rec["c"]))\n' +
      'print("OK" if bad == 0 else ("BAD=%d" % bad))\n' +
      'sys.exit(1 if bad else 0)\n');
    let out, code = 0;
    try { out = execFileSync(PYTHON, [driver, vecPath], { encoding: 'utf8' }); }
    catch (e) { code = e.status; out = (e.stdout || '') + (e.stderr || ''); }
    fs.rmSync(dir, { recursive: true, force: true });
    assert.strictEqual(code, 0, `a Python kanonizalas eltert a JS-tol:\n${out}`);
  });

  // ── 2. Egyetertes valid logon ────────────────────────────────────────────────
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-cx-log-'));
  await buildLog(dir);

  await check('egyetertes (valid): JS verifier 0 ES Python verifier 0', () => {
    const js = runJsVerify(dir);
    const py = runPyVerify(dir);
    assert.strictEqual(js.code, 0, `JS verifier nem 0:\n${js.out}`);
    assert.strictEqual(py.code, 0, `Python verifier nem 0:\n${py.out}`);
    assert.ok(/MAG ERVENYES/.test(py.out), 'a Python verifier nem jelezte az ervenyesseget');
  });

  // ── 3. Egyetertes tampereken ─────────────────────────────────────────────────
  const tampers = [
    ['torzs-hamisitas', (rs) => { rs[0].io.output_hash = core.sha256('HAMIS'); }],
    ['inclusion proof elrontasa', (rs) => { const r = rs.find(x => x.anchor_ref); r.anchor_ref.inclusion_proof[0] = 'sha256:' + '0'.repeat(64); }],
    ['chain_root_hash hamisitas (re-sign)', (rs) => { const wf = rs.find(x => x.receipt_type === 'workflow'); wf.chain_root_hash = core.sha256('hamis'); delete wf.signature; wf.signature = core.signReceipt(wf, priv); }]
  ];

  for (const [name, fn] of tampers) {
    await check(`egyetertes (tamper): "${name}" -> JS 1 ES Python 1`, () => {
      const d2 = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-cx-t-'));
      const rs = fs.readFileSync(path.join(dir, 'receipts.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
      fn(rs);
      fs.writeFileSync(path.join(d2, 'receipts.jsonl'), rs.map(r => JSON.stringify(r)).join('\n') + '\n');
      fs.copyFileSync(path.join(dir, 'sth.jsonl'), path.join(d2, 'sth.jsonl'));
      fs.copyFileSync(path.join(dir, 'anchors.jsonl'), path.join(d2, 'anchors.jsonl'));
      fs.writeFileSync(path.join(d2, 'public-key.pem'), pub);
      const js = runJsVerify(d2);
      const py = runPyVerify(d2);
      fs.rmSync(d2, { recursive: true, force: true });
      assert.strictEqual(js.code, 1, `JS nem utasitotta el:\n${js.out}`);
      assert.strictEqual(py.code, 1, `Python nem utasitotta el:\n${py.out}`);
    });
  }

  fs.rmSync(dir, { recursive: true, force: true });
  console.log('-'.repeat(72));
  if (process.exitCode === 1) {
    console.log(`EREDMENY: NEM minden teszt zold (${passed} sikeres).`);
  } else {
    console.log(`EREDMENY: mind a ${passed} teszt zold. A JS es a Python implementacio egyezik.`);
  }
})();
