#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════════════
// AXR - Key succession epito / ellenorzo CLI (0.5)
// ═══════════════════════════════════════════════════════════════════════════════
// A key_succession egy root-kulccsal alairt rekord, ami egy operator-kulcs
// rotaciojat autorizalja: a predecessor (fingerprint) -> successor (teljes
// publikus kulcs) valtast, egy tree_size hatartol (effective_from_tree_size).
// A root-kulcs az operatortol FUGGETLEN fel tulajdona - ugyanaz, ami a
// trust-rootot alairja. A rekordot a sidecar az utod elso STH-jaba agyazza
// (axr-anchor --succession), a monitor es a verifier a root-kulccsal verifikalja.
//
// Hasznalat:
//   # uj succession epitese (a predecessor PEM-bol vagy kesz fingerprintbol)
//   node axr-key-succession.js build <root-priv.pem> \
//        --log-id axr:agent:v1 --role sth|receipt \
//        --predecessor <regi-pub.pem> | --predecessor-fingerprint sha256:<hex> \
//        --successor <uj-pub.pem> --effective-from <tree_size> [--reason szoveg] \
//        > key-succession.json
//
//   # meglevo rekord ellenorzese a root publikus kulccsal VAGY trust-roottal
//   # (trust-root eseten eloszor maga a trust-root verifikal, es a benne levo
//   #  root_public_key-jel ellenorzunk - igy a bizalmi horgony egyetlen fajl)
//   node axr-key-succession.js verify <key-succession.json> <root-pub.pem | trust-root.json>
//
//   # kulcs-fingerprint kiirasa (a --predecessor-fingerprint elokeszitesehez)
//   node axr-key-succession.js fingerprint <pub.pem>
//
// Nulla kulso fuggoseg. Kilepesi kod: 0 ok, 1 ervenytelen, 2 rossz hasznalat.
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const succ = require('./axr-succession');

function die(msg, code) { console.error(msg); process.exit(code == null ? 2 : code); }
function readFileOrDie(p, label) {
  try { return fs.readFileSync(p, 'utf8'); }
  catch (e) { die('HIBA: a(z) ' + label + ' nem olvashato: ' + e.message); }
}

const [,, cmd, ...rest] = process.argv;

// ── build ──────────────────────────────────────────────────────────────────────
if (cmd === 'build') {
  const positional = [];
  const flags = {};
  for (let i = 0; i < rest.length; i++) {
    if (rest[i].startsWith('--')) { flags[rest[i].slice(2)] = rest[i + 1]; i++; }
    else positional.push(rest[i]);
  }
  const [rootPrivPath] = positional;
  const usage = 'Hasznalat: node axr-key-succession.js build <root-priv.pem> ' +
    '--log-id <id> --role sth|receipt (--predecessor <pub.pem> | --predecessor-fingerprint sha256:<hex>) ' +
    '--successor <pub.pem> --effective-from <tree_size> [--reason szoveg]';
  if (!rootPrivPath || !flags['log-id'] || !flags.role || !flags.successor || !flags['effective-from'])
    die(usage);
  if (!flags.predecessor && !flags['predecessor-fingerprint'])
    die(usage + '\nA predecessor kotelezo: PEM fajl (--predecessor) vagy kesz fingerprint (--predecessor-fingerprint).');

  const rootPriv = readFileOrDie(rootPrivPath, 'root privat kulcs');
  const successorPem = readFileOrDie(flags.successor, 'successor publikus kulcs');
  const predecessorFp = flags['predecessor-fingerprint'] ||
    succ.keyFingerprint(readFileOrDie(flags.predecessor, 'predecessor publikus kulcs'));
  const effectiveFrom = Number(flags['effective-from']);

  let record;
  try {
    record = succ.buildKeySuccession({
      log_id: flags['log-id'],
      role: flags.role,
      predecessor_fingerprint: predecessorFp,
      successor_public_key: successorPem,
      effective_from_tree_size: effectiveFrom,
      reason: flags.reason
    }, rootPriv);
  } catch (e) { die('HIBA: ' + e.message); }

  // onellenorzes mielott kiirjuk (mint a trust-root CLI): a most epitett rekord
  // a sajat root-kulcsunkkal verifikal-e
  let rootPub;
  try {
    rootPub = require('crypto').createPublicKey(
      require('crypto').createPrivateKey(rootPriv)).export({ type: 'spki', format: 'pem' });
  } catch (e) { die('HIBA: a root kulcsbol nem kepezheto publikus kulcs: ' + e.message); }
  const chk = succ.verifyKeySuccession(record, rootPub);
  if (!chk.ok) die('HIBA: a felepitett succession nem verifikal: ' + chk.problems.join('; '), 1);

  process.stdout.write(JSON.stringify(record) + '\n');
  process.exit(0);
}

// ── verify ─────────────────────────────────────────────────────────────────────
if (cmd === 'verify') {
  const [recordPath, anchorPath] = rest;
  if (!recordPath || !anchorPath)
    die('Hasznalat: node axr-key-succession.js verify <key-succession.json> <root-pub.pem | trust-root.json>');

  let record;
  try { record = JSON.parse(readFileOrDie(recordPath, 'succession rekord')); }
  catch (e) { die('HIBA: a succession rekord ervenytelen JSON: ' + e.message); }

  // A bizalmi horgony lehet nyers PEM vagy alairt trust-root. Trust-root eseten
  // ELOSZOR a trust-root verifikal (onmagaval), es csak utana hasznaljuk a
  // root_public_key-jet - igy nem lehet egy hamis fajllal "sajat rootot" hozni.
  const anchorRaw = readFileOrDie(anchorPath, 'bizalmi horgony (root-pub / trust-root)');
  let rootPub;
  if (anchorRaw.trimStart().startsWith('-----BEGIN')) {
    rootPub = anchorRaw;
  } else {
    let tr;
    try { tr = JSON.parse(anchorRaw); }
    catch (e) { die('HIBA: a bizalmi horgony se nem PEM, se nem ervenyes JSON: ' + e.message); }
    const trChk = succ.verifyTrustRoot(tr);
    if (!trChk.ok) die('HIBA: a trust-root NEM verifikal: ' + trChk.problems.join('; '), 1);
    rootPub = tr.root_public_key;
  }

  const res = succ.verifyKeySuccession(record, rootPub);
  if (res.ok) {
    console.log('Key succession ERVENYES (root-alairt).');
    console.log('  log_id:         ' + record.log_id);
    console.log('  role:           ' + record.role);
    console.log('  predecessor:    ' + record.predecessor_fingerprint);
    console.log('  successor:      ' + record.successor_fingerprint);
    console.log('  effective_from: tree_size >= ' + record.effective_from_tree_size);
    console.log('  reason:         ' + record.reason + '  (issued_at: ' + record.issued_at + ')');
    process.exit(0);
  } else {
    console.log('Key succession ERVENYTELEN: ' + res.problems.join('; '));
    process.exit(1);
  }
}

// ── fingerprint ────────────────────────────────────────────────────────────────
if (cmd === 'fingerprint') {
  const [pemPath] = rest;
  if (!pemPath) die('Hasznalat: node axr-key-succession.js fingerprint <pub.pem>');
  console.log(succ.keyFingerprint(readFileOrDie(pemPath, 'publikus kulcs')));
  process.exit(0);
}

die('Hasznalat: node axr-key-succession.js <build|verify|fingerprint> ...');
