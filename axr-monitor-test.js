// ═══════════════════════════════════════════════════════════════════════════════
// AXR 0.3 Stage D - a fuggetlen Monitor tesztje
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-monitor-test.js
//
// Mit ellenoriz:
//   1. tisztesseges novekedes: a monitor elfogadja a sidecar altal keszitett
//      egymast koveto STH-kat (journal max=3, majd 6), a consistency tart
//   2. idempotencia: ugyanazon adat ujrapollozasa nem ad sertest
//   3. EQUIVOCATION: ha a mar naplozott tree_size-hoz mas root jelenik meg,
//      a monitor elfogja (az operator ket kulonbozo fat mutatott)
//   4. TRUNCATION: ha a log zsugorodik (kisebb max tree_size, mint a naplozott),
//      a monitor elfogja
//   5. ROOT_MISMATCH: ha egy alairt STH rootja nem egyezik a tenyleges receiptek
//      Merkle-gyokerevel (friss journal, hogy az equivocation ne fedje el)
//   6. BAD_SIGNATURE: egy megmasitott (nem ujraalairt) STH-t a monitor elutasit
//   7. compare: ket monitor journalja kozotti split-view bizonyitasa
//
// Nulla kulso fuggoseg.  Kilepesi kod: 0 ha minden zold, 1 ha barmi megbukik.
// ═══════════════════════════════════════════════════════════════════════════════

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const axr = require('./axr-core');
const { runAnchor } = require('./axr-anchor');
const { pollMonitor, compareJournals } = require('./axr-monitor');

let passed = 0;
async function check(name, fn) {
  try { await fn(); passed++; console.log(`  ok  - ${name}`); }
  catch (e) { console.log(`  HIBA - ${name}\n        ${e.message}`); process.exitCode = 1; }
}

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
const pubPem = publicKey.export({ type: 'spki', format: 'pem' });
const fixedNow = () => '2026-06-06T08:00:00.000Z';

function sign(obj) { const r = { ...obj }; delete r.signature; r.signature = axr.signReceipt(r, privPem); return r; }

// Egy workflow-futas: 2 lepes + 1 workflow receipt, helyesen lancolva.
function makeRun(prevWorkflowHash, tag) {
  const wfId = axr.uuid();
  const steps = [];
  let prev = null;
  for (let i = 0; i < 2; i++) {
    const s = sign({
      axr_version: '0.3', receipt_type: 'step', receipt_id: axr.uuid(),
      workflow_receipt_id: wfId, sequence: i + 1,
      step: { node_name: `N${i}`, kind: 'deterministic', deterministic: true, model: null },
      io: { input_hash: axr.sha256(`${tag}-in-${i}`), output_hash: axr.sha256(`${tag}-out-${i}`), decision: null },
      inputs: [], previous_receipt_hash: prev, anchor_ref: null
    });
    steps.push(s); prev = axr.chainHash(s);
  }
  const wf = sign({
    axr_version: '0.3', receipt_type: 'workflow', receipt_id: wfId,
    workflow: { workflow_id: 'wf', trigger_timestamp: 't' },
    outcome: { final_status: tag }, step_chain: steps.map(s => s.receipt_id),
    chain_root_hash: axr.chainHash(steps[steps.length - 1]),
    previous_receipt_hash: prevWorkflowHash || null, anchor_ref: null
  });
  return { leafReceipts: [...steps, wf], workflowHash: axr.chainHash(wf) };
}

function newDir() { return fs.mkdtempSync(path.join(os.tmpdir(), 'axr-mon-')); }

// Tisztesseges, ket-futasos, lehorgonyzott log felepitese (STH1 size=3, STH2 size=6)
async function buildHonestLog() {
  const dir = newDir();
  const receiptsPath = path.join(dir, 'receipts.jsonl');
  const run1 = makeRun(null, 'ZONE_INCOMPATIBLE');
  fs.writeFileSync(receiptsPath, run1.leafReceipts.map(r => JSON.stringify(r)).join('\n') + '\n');
  await runAnchor({ receiptsPath, privateKeyPem: privPem, backends: ['local'], now: fixedNow });
  const run2 = makeRun(run1.workflowHash, 'DAY_FULL');
  fs.appendFileSync(receiptsPath, run2.leafReceipts.map(r => JSON.stringify(r)).join('\n') + '\n');
  await runAnchor({ receiptsPath, privateKeyPem: privPem, backends: ['local'], now: fixedNow });
  return { dir, receiptsPath, sthPath: path.join(dir, 'sth.jsonl'), anchorsPath: path.join(dir, 'anchors.jsonl') };
}

(async () => {
  // ── 1-2. tisztesseges novekedes + idempotencia ────────────────────────────────
  const honest = await buildHonestLog();
  const statePath = path.join(honest.dir, 'monitor-state.json');

  await check('tisztesseges log: a monitor elfogadja, journal max=6', () => {
    const res = pollMonitor({ sthPath: honest.sthPath, publicKeyPem: pubPem, statePath,
      receiptsPath: honest.receiptsPath, anchorsPath: honest.anchorsPath, now: fixedNow });
    assert.ok(res.ok, 'sertest jelzett tisztesseges logra: ' + JSON.stringify(res.violations));
    assert.strictEqual(res.journalMax, 6, `journal max 6 helyett ${res.journalMax}`);
    assert.strictEqual(res.witnessedCount, 2, `2 STH helyett ${res.witnessedCount}`);
  });

  await check('idempotencia: ujrapoll ugyanazon adatra -> ok', () => {
    const res = pollMonitor({ sthPath: honest.sthPath, publicKeyPem: pubPem, statePath,
      receiptsPath: honest.receiptsPath, now: fixedNow });
    assert.ok(res.ok, 'idempotens poll sertest jelzett: ' + JSON.stringify(res.violations));
    assert.strictEqual(res.witnessedCount, 2);
  });

  // ── 3. EQUIVOCATION ───────────────────────────────────────────────────────────
  await check('EQUIVOCATION: mas root a mar naplozott tree_size-hoz -> elfogva', () => {
    // alternativ (hamis) fa 3 levellel, ujraalairt STH ugyanarra a tree_size=3-ra
    const altLeaves = [1, 2, 3].map(i => axr.leafHash({ fake: i }));
    const evilSth = sign({ axr_version: '0.3', record_type: 'sth', log_id: 'axr:default:v1',
      tree_size: 3, root_hash: axr.merkleRootFromLeaves(altLeaves),
      timestamp: 't', previous_sth_hash: null });
    const evilPath = path.join(honest.dir, 'sth-evil.jsonl');
    fs.writeFileSync(evilPath, JSON.stringify(evilSth) + '\n');
    // a mar feltoltott journal ellen pollozunk (receptek nelkul, hogy csak az equivocation szoljon)
    const res = pollMonitor({ sthPath: evilPath, publicKeyPem: pubPem, statePath, now: fixedNow });
    assert.ok(!res.ok, 'nem fogta el az equivocationt');
    assert.ok(res.violations.some(v => v.code === 'EQUIVOCATION'), 'nem EQUIVOCATION kodot adott: ' + JSON.stringify(res.violations));
  });

  // ── 4. TRUNCATION ─────────────────────────────────────────────────────────────
  await check('TRUNCATION: zsugorodott log (csak az elso STH) -> elfogva', () => {
    // friss journal, ami mar latta a 6-os maxot
    const dir2 = newDir();
    const st = path.join(dir2, 'state.json');
    pollMonitor({ sthPath: honest.sthPath, publicKeyPem: pubPem, statePath: st, receiptsPath: honest.receiptsPath, now: fixedNow });
    // most csak az elso (size=3) STH-t mutatjuk
    const sths = fs.readFileSync(honest.sthPath, 'utf8').trim().split('\n');
    const truncPath = path.join(dir2, 'sth-trunc.jsonl');
    fs.writeFileSync(truncPath, sths[0] + '\n');
    const res = pollMonitor({ sthPath: truncPath, publicKeyPem: pubPem, statePath: st, now: fixedNow });
    assert.ok(!res.ok, 'nem fogta el a truncationt');
    assert.ok(res.violations.some(v => v.code === 'TRUNCATION'), 'nem TRUNCATION: ' + JSON.stringify(res.violations));
  });

  // ── 4b. TRUNCATION-TO-ZERO (regresszio, 2026-06-10) ──────────────────────────
  // A korai "nincs STH a fajlban" return a 6-os check ELOTT futott le, igy a
  // TELJESEN kiuritett folyam nema exit 0 maradt - pedig ez a truncation
  // legszelsosegesebb esete. A fix utan: ures folyam + nem-ures journal = SERTES.
  await check('TRUNCATION-TO-ZERO: teljesen kiuritett STH-folyam -> elfogva', () => {
    const dir2 = newDir();
    const st = path.join(dir2, 'state.json');
    pollMonitor({ sthPath: honest.sthPath, publicKeyPem: pubPem, statePath: st, receiptsPath: honest.receiptsPath, now: fixedNow });
    const emptyPath = path.join(dir2, 'sth-empty.jsonl');
    fs.writeFileSync(emptyPath, '');
    const res = pollMonitor({ sthPath: emptyPath, publicKeyPem: pubPem, statePath: st, now: fixedNow });
    assert.ok(!res.ok, 'nem fogta el a teljes kiuritest');
    assert.ok(res.violations.some(v => v.code === 'TRUNCATION'), 'nem TRUNCATION: ' + JSON.stringify(res.violations));
    // friss (ures) journal mellett az ures folyam tovabbra is artalmatlan notice
    const st2 = path.join(dir2, 'state2.json');
    const res2 = pollMonitor({ sthPath: emptyPath, publicKeyPem: pubPem, statePath: st2, now: fixedNow });
    assert.ok(res2.ok, 'ures journal + ures folyam nem lehet sertes');
  });

  // ── 5. ROOT_MISMATCH ──────────────────────────────────────────────────────────
  await check('ROOT_MISMATCH: alairt STH rootja != receiptek gyokere -> elfogva', () => {
    const dir3 = newDir();
    // valodi receiptek (3 level)
    const run = makeRun(null, 'X');
    const rp = path.join(dir3, 'receipts.jsonl');
    fs.writeFileSync(rp, run.leafReceipts.map(r => JSON.stringify(r)).join('\n') + '\n');
    // STH, ami HAMIS rootot allit a tree_size=3-ra (de helyesen alairva)
    const badRootSth = sign({ axr_version: '0.3', record_type: 'sth', log_id: 'axr:default:v1',
      tree_size: 3, root_hash: axr.sha256('teljesen-mas-root'), timestamp: 't', previous_sth_hash: null });
    const sp = path.join(dir3, 'sth.jsonl');
    fs.writeFileSync(sp, JSON.stringify(badRootSth) + '\n');
    const res = pollMonitor({ sthPath: sp, publicKeyPem: pubPem, statePath: path.join(dir3, 'state.json'),
      receiptsPath: rp, now: fixedNow });
    assert.ok(!res.ok, 'nem fogta el a root-mismatchet');
    assert.ok(res.violations.some(v => v.code === 'ROOT_MISMATCH'), 'nem ROOT_MISMATCH: ' + JSON.stringify(res.violations));
  });

  // ── 6. BAD_SIGNATURE ──────────────────────────────────────────────────────────
  await check('BAD_SIGNATURE: megmasitott (nem ujraalairt) STH -> elutasitva', () => {
    const dir4 = newDir();
    const run = makeRun(null, 'Y');
    const rp = path.join(dir4, 'receipts.jsonl');
    fs.writeFileSync(rp, run.leafReceipts.map(r => JSON.stringify(r)).join('\n') + '\n');
    const good = sign({ axr_version: '0.3', record_type: 'sth', log_id: 'axr:default:v1',
      tree_size: 3, root_hash: axr.merkleRootFromLeaves(run.leafReceipts.map(axr.leafHash)),
      timestamp: 't', previous_sth_hash: null });
    good.root_hash = axr.sha256('utolagosan-atirt-root'); // alairas utani torzs-modositas
    const sp = path.join(dir4, 'sth.jsonl');
    fs.writeFileSync(sp, JSON.stringify(good) + '\n');
    const res = pollMonitor({ sthPath: sp, publicKeyPem: pubPem, statePath: path.join(dir4, 'state.json'), now: fixedNow });
    assert.ok(!res.ok, 'nem fogta el a rossz alairast');
    assert.ok(res.violations.some(v => v.code === 'BAD_SIGNATURE'), 'nem BAD_SIGNATURE: ' + JSON.stringify(res.violations));
  });

  // ── 7. compare: split-view ket monitor kozott ─────────────────────────────────
  await check('compare: ket monitor eltero size-3 rootja -> EQUIVOCATION bizonyitva', () => {
    const journalA = { log_id: 'axr:default:v1', public_key_fingerprint: 'fp',
      witnessed: [{ tree_size: 3, root_hash: axr.sha256('A-fa') }] };
    const journalB = { log_id: 'axr:default:v1', public_key_fingerprint: 'fp',
      witnessed: [{ tree_size: 3, root_hash: axr.sha256('B-fa') }] };
    const res = compareJournals(journalA, journalB);
    assert.ok(res.equivocationDetected, 'nem detektalta a split-view-t');
    assert.ok(res.conflicts.some(c => c.tree_size === 3), 'nem a 3-as meretnel jelezte');

    // azonos journalokra NINCS konfliktus
    const same = compareJournals(journalA, journalA);
    assert.ok(!same.equivocationDetected, 'azonos journalra hibasan jelzett');
  });

  console.log('-'.repeat(72));
  if (process.exitCode === 1) {
    console.log(`EREDMENY: NEM minden teszt zold (${passed} sikeres). Lasd a [HIBA] sorokat.`);
  } else {
    console.log(`EREDMENY: mind a ${passed} teszt zold. A fuggetlen Monitor mukodik.`);
  }
})();
