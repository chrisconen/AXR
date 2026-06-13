#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════════════
// AXR dogfood - a fejlesztesi naplo, mint verifikalhato AXR-log (teljes 1.0 stack)
// ═══════════════════════════════════════════════════════════════════════════════
// "AXR records and verifies the integrity of its OWN development journal."
//
// A agents/journal.jsonl (a Fable/Meridian/NEXUS munkapad naploja) -> aláírt
// receiptek -> anchorolt STH-k -> a reviewer-agensek (Meridian, NEXUS) witness-
// cosignature-ei -> a teljes 1.0 verifikacio. Egy valos (nem-fixture) AXR-log.
//
// OSZINTE HATAR (N1 + fuggetlenseg):
//   - A receiptek azt bizonyitjak, hogy a naplo NEM valtozott az alairas ota -
//     NEM azt, hogy a bejegyzesek tartalmilag igazak voltak. (Ha az AI hibat
//     irt be, az AXR azt bizonyitja, hogy tenyleg azt irta akkor, es utolag
//     senki sem kozmetikazta ki.)
//   - A LOKALIS demo SZIMULALJA a fuggetlen witness-custody-t (a kulcsok egy
//     gepen). ELESBEN a witnessek kulon biztonsagi zonakban futnak (Fable@
//     Anthropic, NEXUS@Google, Meridian@kulon processz) - ez a valodi
//     zero-trust. A demo NEM allit valodi fuggetlenseget co-located kulcsokkal.
//
// Modulkent: buildDevlog(opts) -> a teljes artefaktum egy konyvtarban + verdikt.
// CLI-kent: 'npm run dogfood' (elo generalas+verifikacio efemer kulcsokkal) vagy
//           'node axr-dogfood.js --out devlog/ [--keys <dir>]'.
//
// Nulla kulso fuggoseg - csak a kozos AXR-modulok.
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const core = require('./axr-core');
const succ = require('./axr-succession');
const control = require('./axr-control');
const { buildJournalReceipts, JOURNAL_LOG_ID } = require('./axr-journal-receipts');
const { runAnchor } = require('./axr-anchor');
const { pollMonitor } = require('./axr-monitor');

function genKey() {
  const kp = crypto.generateKeyPairSync('ed25519');
  return { privateKey: kp.privateKey.export({ type: 'pkcs8', format: 'pem' }),
           publicKey: kp.publicKey.export({ type: 'spki', format: 'pem' }) };
}

// A teljes dev-log artefaktum felepitese egy konyvtarba.
//   opts: { journalPath, outDir, now, keys? } - keys: { root, op, meridian, nexus } PEM-parok
// -> { dir, files, verdict, agents, entryCount }
function buildDevlog(opts) {
  const now = opts.now || (() => new Date().toISOString());
  const dir = opts.outDir;
  fs.mkdirSync(dir, { recursive: true });
  const LOG = JOURNAL_LOG_ID;

  // kulcsok: root (bizalmi horgony), op (dev-log alairo), meridian + nexus (witness).
  // GENUINE-fuggetlen mod (opts.witnesses): a witness PUBLIKUS kulcsait a kulso
  // agensek adjak (a privat kulcsot az orchestrator NEM birtokolja); ilyenkor
  // belso witness-keygen es belso cosign NINCS - a cosignature-okat az agensek
  // sajat processzben allitjak elo (lasd opts.skipCosign).
  const K = opts.keys || { root: genKey(), op: genKey(), meridian: genKey(), nexus: genKey() };
  const witnessList = opts.witnesses || [
    { name: 'meridian', public_key: K.meridian.publicKey },
    { name: 'nexus', public_key: K.nexus.publicKey }];

  const entries = fs.readFileSync(opts.journalPath, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);

  // 1. trust-root: genesis sth+receipt = az op kulcs; witness-kor a control logban
  const trustRoot = succ.buildTrustRoot({ providers: [],
    logs: [{ log_id: LOG, genesis: { sth: K.op.publicKey, receipt: K.op.publicKey } }] },
    K.root.privateKey, K.root.publicKey, now);
  // witness_set: a reviewer-agensek (Meridian, NEXUS), threshold 2
  const witnessSet = succ.buildWitnessSet({ log_id: LOG, witness_threshold: 2, effective_from_tree_size: 1,
    witnesses: witnessList }, K.root.privateKey, now);

  // 2. receiptek a naplobol (az op kulcs irja ala)
  const { receipts, agents } = buildJournalReceipts(entries, K.op.privateKey, LOG);
  const files = {
    receipts: path.join(dir, 'receipts.jsonl'),
    sth: path.join(dir, 'sth.jsonl'),
    anchors: path.join(dir, 'anchors.jsonl'),
    control: path.join(dir, 'control.jsonl'),
    trustRoot: path.join(dir, 'trust-root.json'),
    opPub: path.join(dir, 'op.pubkey.pem')
  };
  fs.writeFileSync(files.receipts, receipts.map(r => JSON.stringify(r)).join('\n') + '\n');
  fs.writeFileSync(files.control, JSON.stringify(witnessSet) + '\n');
  fs.writeFileSync(files.trustRoot, JSON.stringify(trustRoot) + '\n');
  fs.writeFileSync(files.opPub, K.op.publicKey);

  // 3. anchor: az op kulcs irja ala az STH-t, a witness_set-re commitolva
  // (szinkron, determinisztikus 'local' backend; nincs halozat)
  return runAnchor({ receiptsPath: files.receipts, sthPath: files.sth, anchorsPath: files.anchors,
    backends: ['local'], logId: LOG, now, privateKeyPem: K.op.privateKey,
    controlPath: files.control, controlTrustRootPath: files.trustRoot
  }).then(() => {
    // 4. cosign. GENUINE mod (opts.skipCosign): az orchestrator NEM cosignol -
    // a cosignature-okat a kulso agensek allitjak elo, a hivo adja be oket
    // opts.applyCosignatures(sthBody)->[cosignature] utjan. Alapesetben (demo)
    // a belso witness-kulcsok cosignolnak.
    if (!opts.skipCosign) {
      const sths = fs.readFileSync(files.sth, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
      const cosigned = sths.map(sth => sth.record_type === 'sth'
        ? succ.assembleWitnessCosignatures(sth, [succ.cosignWitness(sth, K.meridian.privateKey),
                                                 succ.cosignWitness(sth, K.nexus.privateKey)])
        : sth);
      fs.writeFileSync(files.sth, cosigned.map(r => JSON.stringify(r)).join('\n') + '\n');
    }
    const sthCount = fs.readFileSync(files.sth, 'utf8').trim().split('\n').filter(Boolean)
      .map(JSON.parse).filter(x => x.record_type === 'sth').length;

    // 5. verifikacio: monitor (--require-witnesses) + a teljes lanc
    const trRecords = [trustRoot];
    const mon = pollMonitor({ sthPath: files.sth, publicKeyPem: K.op.publicKey,
      statePath: path.join(dir, '.monitor-state.json'), receiptsPath: files.receipts,
      trustRoot: trRecords, control: [witnessSet], requireWitnesses: true, now });

    return { dir, files, agents, entryCount: entries.length, keys: K,
      verdict: { monitor_ok: mon.ok, monitor_violations: mon.violations,
                 monitor_notices: mon.notices, sth_count: sthCount } };
  });
}

module.exports = { buildDevlog };

// ── CLI ──────────────────────────────────────────────────────────────────────
if (require.main === module) {
  const argv = process.argv.slice(2);
  const flags = {};
  for (let i = 0; i < argv.length; i++) if (argv[i].startsWith('--')) { flags[argv[i].slice(2)] = argv[i + 1]; i++; }
  const journalPath = flags.journal || path.join(__dirname, 'agents', 'journal.jsonl');
  const outDir = flags.out || path.join(require('os').tmpdir(), 'axr-devlog-' + process.pid);
  const { execFileSync } = require('child_process');

  buildDevlog({ journalPath, outDir }).then(res => {
    // hiteles verifier-futas (JS) a kimeneten
    const keyPath = res.files.opPub;
    let jsExit = -1;
    try {
      execFileSync('node', [path.join(__dirname, 'axr-verify.js'), res.files.receipts, keyPath,
        res.files.sth, res.files.anchors, '--trust-root', res.files.trustRoot,
        '--control', res.files.control, '--require-witnesses'], { stdio: 'pipe' });
      jsExit = 0;
    } catch (e) { jsExit = e.status == null ? -1 : e.status; }

    console.log('─'.repeat(72));
    console.log('AXR dev-log — "records and verifies the integrity of its own development journal"');
    console.log('─'.repeat(72));
    console.log(`Journal entries: ${res.entryCount}   Agents: ${res.agents.join(', ')}`);
    console.log(`STH count: ${res.verdict.sth_count}   Witnesses: meridian, nexus (threshold 2)`);
    console.log(`Monitor (--require-witnesses): ${res.verdict.monitor_ok ? 'OK' : 'VIOLATIONS: ' + JSON.stringify(res.verdict.monitor_violations)}`);
    console.log(`JS verifier (--require-witnesses): exit ${jsExit}`);
    console.log(`Artefaktum: ${res.dir}`);
    console.log('─'.repeat(72));
    console.log('OSZINTE HATAR: a receiptek a naplo MODOSITHATATLANSAGAT bizonyitjak az alairas ota,');
    console.log('NEM a bejegyzesek tartalmi igazsagat (N1). A lokalis demo SZIMULALJA a fuggetlen');
    console.log('witness-custody-t; elesben a witnessek kulon biztonsagi zonakban futnak.');
    process.exit(res.verdict.monitor_ok && jsExit === 0 ? 0 : 1);
  }).catch(e => { console.error('HIBA:', e.message); process.exit(1); });
}
