// ═══════════════════════════════════════════════════════════════════════════════
// AXR dogfood teszt - a fejlesztesi naplo, mint verifikalhato AXR-log
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-dogfood-test.js   (Python esetek kihagyva, ha nincs)
//
// Mit ellenoriz:
//   1. A generator determinisztikus: ugyanaz a journal + kulcs -> ugyanaz a
//      receipt-log (a receipt_id tartalombol szarmazik, nem random)
//   2. ELO build (efemer kulcsok): a journalbol generalt dev-log a TELJES 1.0
//      stacken zold - monitor (--require-witnesses) + JS + Python verifier
//   3. Tartalom-kotes: egy journal-bejegyzes megvaltoztatasa -> a receipt
//      alairasa torik (a dev-log a sajat naplojahoz kotott)
//   4. A COMMITOLT fagyasztott snapshot (devlog/) verifikal mindket verifierrel
//      (a web-demo artefaktum elo regresszio-zara)
//
// Nulla kulso fuggoseg.  Kilepesi kod: 0 zold, 1 hiba.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const core = require('./axr-core');
const { buildJournalReceipts } = require('./axr-journal-receipts');
const { buildDevlog } = require('./axr-dogfood');

let pass = 0, fail = 0;
function ok(cond, name) { if (cond) { pass++; } else { fail++; console.log('  FAIL: ' + name); } }
function section(t) { console.log('\n' + t); }
function genKey() {
  const kp = crypto.generateKeyPairSync('ed25519');
  return { privateKey: kp.privateKey.export({ type: 'pkcs8', format: 'pem' }),
           publicKey: kp.publicKey.export({ type: 'spki', format: 'pem' }) };
}
function findPython() {
  for (const cand of ['python3', 'python']) {
    try { const v = execFileSync(cand, ['--version'], { encoding: 'utf8', stdio: 'pipe' });
      if (/^Python 3\./.test(v.trim())) return cand; } catch (e) {}
  }
  return null;
}
const PYTHON = findPython();
const T0 = () => '2026-06-13T15:00:00.000Z';

const sampleJournal = [
  { ts: '2026-06-12T06:00:00.000Z', agent: 'fable', what: 'A lepes', why: 'Chris kerese', refs: ['a.js'] },
  { ts: '2026-06-12T07:00:00.000Z', agent: 'meridian', what: 'review', why: 'Fable delegalta', refs: [] },
  { ts: '2026-06-12T08:00:00.000Z', agent: 'nexus', what: 'masik review', why: 'Fable delegalta', refs: ['b.js'] }
];

(async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-dogtest-'));

  // ───────────────────────────────────────────────────────────────────────────
  section('1. Determinizmus');
  const op = genKey();
  const r1 = buildJournalReceipts(sampleJournal, op.privateKey, 'axr:devlog:v1');
  const r2 = buildJournalReceipts(sampleJournal, op.privateKey, 'axr:devlog:v1');
  ok(JSON.stringify(r1.receipts) === JSON.stringify(r2.receipts),
    'ugyanaz a journal + kulcs -> byte-azonos receipt-log');
  ok(r1.receipts.length === sampleJournal.length + 1 && r1.agents.join(',') === 'fable,meridian,nexus',
    '3 step + 1 workflow receipt, az agensek attribualva');
  ok(r1.receipts.every(rec => core.verifyReceipt(rec, op.publicKey)), 'minden receipt verifikal az op kulccsal');

  // ───────────────────────────────────────────────────────────────────────────
  section('2. ELO build a teljes 1.0 stacken (efemer kulcsok)');
  const journalPath = path.join(tmp, 'journal.jsonl');
  fs.writeFileSync(journalPath, sampleJournal.map(e => JSON.stringify(e)).join('\n') + '\n');
  const res = await buildDevlog({ journalPath, outDir: path.join(tmp, 'live'), now: T0 });
  ok(res.verdict.monitor_ok, 'monitor (--require-witnesses): nincs sertes: ' + JSON.stringify(res.verdict.monitor_violations));
  function verifyDir(cmd, d, keyPub) {
    const script = cmd === 'node' ? 'axr-verify.js' : 'axr_verify.py';
    const args = [path.join(__dirname, script), path.join(d, 'receipts.jsonl'), path.join(d, 'op.pubkey.pem'),
      path.join(d, 'sth.jsonl'), path.join(d, 'anchors.jsonl'), '--trust-root', path.join(d, 'trust-root.json'),
      '--control', path.join(d, 'control.jsonl'), '--require-witnesses'];
    try { execFileSync(cmd, args, { stdio: 'pipe' }); return 0; } catch (e) { return e.status == null ? -1 : e.status; }
  }
  ok(verifyDir('node', res.dir) === 0, 'JS verifier (teljes lanc, --require-witnesses): exit 0');
  if (PYTHON) ok(verifyDir(PYTHON, res.dir) === 0, 'Python verifier: exit 0 (cross-impl, valos dev-log)');

  // ───────────────────────────────────────────────────────────────────────────
  section('3. Tartalom-kotes: a naplo megvaltoztatasa torik');
  const recs = fs.readFileSync(path.join(res.dir, 'receipts.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
  const step = recs.find(r => r.receipt_type === 'step');
  step.io.input_summary.what = 'HAMISITOTT bejegyzes';   // nincs ujra-alairas
  ok(!core.verifyReceipt(step, res.keys.op.publicKey), 'egy bejegyzes utolagos atirasa -> a receipt alairasa ERVENYTELEN');

  // ───────────────────────────────────────────────────────────────────────────
  section('4. A COMMITOLT fagyasztott snapshot (devlog/) verifikal');
  const snap = path.join(__dirname, 'devlog');
  if (fs.existsSync(path.join(snap, 'receipts.jsonl'))) {
    ok(verifyDir('node', snap) === 0, 'devlog/ snapshot: JS verifier exit 0 (a web-demo regresszio-zara)');
    if (PYTHON) ok(verifyDir(PYTHON, snap) === 0, 'devlog/ snapshot: Python verifier exit 0');
    // tamper a snapshot egy peldanyan -> elutasitas
    const t = fs.mkdtempSync(path.join(tmp, 'snap-'));
    for (const f of ['receipts.jsonl', 'sth.jsonl', 'anchors.jsonl', 'control.jsonl', 'trust-root.json', 'op.pubkey.pem'])
      fs.copyFileSync(path.join(snap, f), path.join(t, f));
    const sr = fs.readFileSync(path.join(t, 'receipts.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
    const st = sr.find(r => r.receipt_type === 'step'); st.io.input_summary.what = 'TAMPER';
    fs.writeFileSync(path.join(t, 'receipts.jsonl'), sr.map(r => JSON.stringify(r)).join('\n') + '\n');
    ok(verifyDir('node', t) === 1, 'a snapshot tamperelese -> JS verifier exit 1');
  } else {
    console.log('  SKIP - nincs committolt devlog/ snapshot');
  }

  console.log(`\nOsszesen: ${pass} ok, ${fail} hiba` + (PYTHON ? '' : ' (Python esetek kihagyva)'));
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('VARATLAN HIBA:', e); process.exit(1); });
