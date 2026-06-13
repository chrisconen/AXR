#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════════════
// AXR 0.8 - Witness CLI (stateful STH cosigning + verify)
// ═══════════════════════════════════════════════════════════════════════════════
// Egy witness egy operator-tol FUGGETLEN fel (auditor, ugyfel, konzorcium), aki
// cosignol egy STH-t - ezzel a fogyaszto az STH-t threshold-nyi fuggetlen
// alairas alapjan fogadhatja el (megelozo equivocation-vedelem).
//
// A witnessing CSAK akkor preventiv, ha a witness STATEFUL (Meridian-invarians):
// allapotot tart logonkent, es MEGTAGADJA olyan STH cosignolasat, ami nem
// append-only folytatasa az altala utoljara latott STH-nak. Igy egy operator nem
// tud threshold-nyi cosignature-t szerezni egy split-view (equivocalt) agra:
//   - kisebb tree_size mint az utoljara latott -> TRUNCATION, elutasitva;
//   - azonos tree_size DE eltero root_hash -> EQUIVOCATION, elutasitva;
//   - azonos tree_size + azonos root -> idempotens (ujra kiadja a cosignature-t);
//   - nagyobb tree_size -> append-only bovites, elfogadva (es ha consecutive,
//     a previous_sth_hash lancolas is ellenorizve).
//
// Parancsok:
//   sign <sth.jsonl|sth.json> <witness-priv.pem> --state <state.json> [--out <fajl>]
//        -> egy cosignature { witness_fingerprint, signature } a LEGNAGYOBB
//           tree_size-u STH-ra; a state frissul. Elutasitas eseten exit 1.
//   verify <sth-with-cosigs.json> <witness_set.json> <root-pub.pem|trust-root.json>
//        -> az STH cosignature-einek ellenorzese az aktiv witness-keszlet ellen
//           (validCount vs threshold; anomaliak). Exit 0 ha eleri a threshold-ot
//           es nincs anomalia, 1 ha nem.
//
// SUBMISSION-MINTA (a spec resze, operator-oldali implementacio):
//   az operator POST-olja az STH-t a witness HTTP-vegpontjara; a valasz a
//   cosignature JSON. A witness a 'sign' parancsot futtatja a kapott STH-ra.
//   A protokoll a cosignature FORMATUMAT rogziti, nem a transzportot.
//
// Nulla kulso fuggoseg. Kilepesi kod: 0 ok, 1 elutasitas/ervenytelen, 2 hasznalat.
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const crypto = require('crypto');
const axr = require('./axr-core');
const succ = require('./axr-succession');

function die(msg, code) { console.error(msg); process.exit(code == null ? 2 : code); }
function readFileOrDie(p, label) { try { return fs.readFileSync(p, 'utf8'); } catch (e) { die('HIBA: a(z) ' + label + ' nem olvashato: ' + e.message); } }
function readSth(p) {
  const raw = readFileOrDie(p, 'STH fajl').trim();
  const recs = raw.split('\n').filter(Boolean).map(JSON.parse).filter(r => r.record_type === 'sth');
  if (!recs.length) die('HIBA: nincs STH a fajlban: ' + p, 2);
  return recs.sort((a, b) => a.tree_size - b.tree_size)[recs.length - 1]; // a legnagyobb tree_size
}
function loadAnchorOrDie(p) {
  const raw = readFileOrDie(p, 'root-horgony');
  if (raw.trimStart().startsWith('-----BEGIN')) return raw;
  let recs; try { recs = succ.parseTrustRootInput(raw); } catch (e) { die('HIBA: a horgony se nem PEM, se nem JSON: ' + e.message); }
  const cv = succ.verifyTrustRootChain(recs);
  if (!cv.ok) die('HIBA: a trust-root (lanc) nem verifikal: ' + cv.problems.join('; '), 1);
  return cv.effective;
}

const argv = process.argv.slice(2);
const cmd = argv[0];
const rest = argv.slice(1);
const positional = [];
const flags = {};
for (let i = 0; i < rest.length; i++) {
  if (rest[i].startsWith('--')) { flags[rest[i].slice(2)] = rest[i + 1]; i++; }
  else positional.push(rest[i]);
}

// ── sign: stateful cosignolas ──────────────────────────────────────────────────
if (cmd === 'sign') {
  const [sthPath, privPath] = positional;
  if (!sthPath || !privPath || !flags.state)
    die('Hasznalat: node axr-witness.js sign <sth.jsonl|sth.json> <witness-priv.pem> --state <state.json> [--out <fajl>]');
  const sth = readSth(sthPath);
  const priv = readFileOrDie(privPath, 'witness privat kulcs');
  if (!sth.log_id) die('HIBA: az STH-bol hianyzik a log_id', 2);

  // witness-allapot betoltese (logonkent)
  let state = {};
  if (fs.existsSync(flags.state)) {
    try { state = JSON.parse(fs.readFileSync(flags.state, 'utf8')); } catch (e) { die('HIBA: a state fajl ervenytelen JSON: ' + e.message); }
  }
  const prev = state[sth.log_id] || null;
  const sthHash = axr.chainHash(sth);

  // STATEFUL append-only ellenorzes (a preventiv invarians)
  if (prev) {
    if (sth.tree_size < prev.tree_size)
      die(`ELUTASITVA (TRUNCATION): a kert STH tree_size-a (${sth.tree_size}) KISEBB az utoljara cosignolt fanal (${prev.tree_size}) - a witness nem cosignol zsugorodast.`, 1);
    if (sth.tree_size === prev.tree_size && sth.root_hash !== prev.root_hash)
      die(`ELUTASITVA (EQUIVOCATION): azonos tree_size (${sth.tree_size}) DE eltero root_hash - a witness mar cosignolt egy MAS fat erre a meretre. Ez split-view kiserlet.`, 1);
    if (sth.tree_size > prev.tree_size && sth.previous_sth_hash && prev.sth_hash &&
        prev.consecutive_hint && sth.previous_sth_hash !== prev.sth_hash) {
      // gyenge lanc-jelzes: ha a kovetkezo STH kozvetlenul az elozore hivatkozik,
      // de nem arra mutat, az gyanus (de a witness nem latja az osszes kozteso
      // STH-t, ezert csak figyelmeztetunk, nem utasitunk el)
      console.error('FIGYELEM: a previous_sth_hash nem az utoljara latott STH-ra mutat (lehet kozteso STH, amit a witness nem latott).');
    }
  }

  const cosig = succ.cosignWitness(sth, priv);
  // allapot frissitese
  state[sth.log_id] = { tree_size: sth.tree_size, root_hash: sth.root_hash, sth_hash: sthHash,
    updated_at: new Date().toISOString() };
  const stateText = JSON.stringify(state, null, 2) + '\n';
  // Alapban atomi csere (tmp -> rename), hogy egy felbeszakado iras ne hagyjon
  // torrent (torn) state-fajlt. Egyes fajlrendszereken (sandbox, fajlzarolas,
  // viruskereso, halozati FS) a rename EPERM-et dob; ilyenkor - vagy ha az
  // operator az AXR_WITNESS_NO_ATOMIC env-kapcsoloval kikenyszeriti - kozvetlen
  // iras a fallback. A state-frissites igy is helyes; a cosignature kibocsatasat
  // (a determinisztikus, allapotmentes alairast) ez sosem blokkolhatja.
  if (process.env.AXR_WITNESS_NO_ATOMIC) {
    fs.writeFileSync(flags.state, stateText);
  } else {
    const tmp = flags.state + '.tmp';
    fs.writeFileSync(tmp, stateText);
    try {
      fs.renameSync(tmp, flags.state);
    } catch (e) {
      fs.writeFileSync(flags.state, stateText);
      try { fs.unlinkSync(tmp); } catch (_) {}
    }
  }

  const out = JSON.stringify(cosig) + '\n';
  if (flags.out) { fs.writeFileSync(flags.out, out); console.error(`Cosignolva: tree_size=${sth.tree_size}, witness=${cosig.witness_fingerprint.slice(0, 20)}... -> ${flags.out}`); }
  else process.stdout.write(out);
  process.exit(0);
}

// ── verify: STH cosignature-ok ellenorzese az aktiv witness-keszlet ellen ──────
if (cmd === 'verify') {
  const [sthPath, witnessSetPath, anchorPath] = positional;
  if (!sthPath || !witnessSetPath || !anchorPath)
    die('Hasznalat: node axr-witness.js verify <sth-with-cosigs.json> <witness_set.json> <root-pub.pem|trust-root.json>');
  const sth = readSth(sthPath);
  let witnessSet; try { witnessSet = JSON.parse(readFileOrDie(witnessSetPath, 'witness_set')); } catch (e) { die('HIBA: witness_set ervenytelen JSON: ' + e.message); }
  const anchor = loadAnchorOrDie(anchorPath);

  const wv = succ.verifyWitnessSet(witnessSet, anchor);
  if (!wv.ok) die('HIBA: a witness_set nem verifikal a root-horgonyra: ' + wv.problems.join('; '), 1);
  // a witness_set -> idovonal-bejegyzes alak (a fingerprint+pem feloldashoz)
  const tl = succ.buildWitnessTimeline([witnessSet], anchor);
  const entry = tl.timeline[0];
  const res = succ.verifyWitnessCosignatures(sth, entry);
  console.log(`Witness cosignatures @ tree_size=${sth.tree_size}: ${res.validCount}/${res.threshold} ervenyes` +
    (res.anomalies.length ? `, ${res.anomalies.length} anomalia` : ''));
  for (const a of res.anomalies) console.log('  [anomalia] ' + a);
  if (res.anomalies.length) { console.log('EREDMENY: ERVENYTELEN (anomalia a cosignature-okban).'); process.exit(1); }
  if (res.validCount < res.threshold) { console.log(`EREDMENY: UNDER_WITNESSED (${res.validCount} < threshold ${res.threshold}).`); process.exit(1); }
  console.log('EREDMENY: a threshold teljesul, a cosignature-ok ervenyesek.');
  process.exit(0);
}

die('Hasznalat: node axr-witness.js <sign|verify> ...');
