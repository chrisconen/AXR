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
// 0.6 - revokacio es kvorum-ceremonia:
//   # egykulcsos revokacio (kvorumhoz: body/sign/assemble)
//   node axr-key-succession.js revoke <root-priv.pem> --log-id ... --role ... \
//        (--revoked <pub.pem> | --revoked-fingerprint sha256:<hex>) --revoked-at <n>
//
//   # tobb-alairos (M-of-N) ceremonia, kulon gepeken:
//   node axr-key-succession.js body succession|revocation|root-successor ... > body.json
//   node axr-key-succession.js sign body.json alairo1-priv.pem > part1.json   # alaironkent
//   node axr-key-succession.js assemble body.json part1.json part2.json \
//        --verify trust-root.json > record.json
//
// A verify mindharom horgonyt fogadja: nyers PEM, trust-root, trust-root LANC -
// es key_succession ES key_revocation rekordot is ellenoriz.
//
// 0.7 - control log:
//   node axr-key-succession.js control add <control.jsonl> <rekord.json> --trust-root <horgony> [--log-id id]
//   node axr-key-succession.js control verify <control.jsonl> <horgony> [--log-id id]
//   node axr-key-succession.js control status <control.jsonl> <trust-root> --log-id id [--at <tree_size>]
//
// Nulla kulso fuggoseg. Kilepesi kod: 0 ok, 1 ervenytelen, 2 rossz hasznalat.
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const crypto = require('crypto');
const succ = require('./axr-succession');

function die(msg, code) { console.error(msg); process.exit(code == null ? 2 : code); }
function readFileOrDie(p, label) {
  try { return fs.readFileSync(p, 'utf8'); }
  catch (e) { die('HIBA: a(z) ' + label + ' nem olvashato: ' + e.message); }
}
function readJsonlOrDie(p) {
  const raw = readFileOrDie(p, 'JSONL fajl (' + p + ')').trim();
  if (!raw) return [];
  try { return raw.split('\n').filter(Boolean).map(JSON.parse); }
  catch (e) { return die('HIBA: ervenytelen JSONL (' + p + '): ' + e.message); }
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

// ── kozos: bizalmi horgony betoltese ───────────────────────────────────────────
// Lehet nyers PEM, egyetlen trust-root, vagy trust-root LANC (0.6). JSON eseten
// ELOSZOR a rekord/lanc verifikal onmagaban (a fej a pinned genesis), es az
// EFFEKTIV (utolso) root lesz a horgony - hamis fajlbol nem lesz "sajat root".
function loadAnchorOrDie(anchorPath) {
  const raw = readFileOrDie(anchorPath, 'bizalmi horgony (root-pub / trust-root / lanc)');
  if (raw.trimStart().startsWith('-----BEGIN')) return raw;
  let records;
  try { records = succ.parseTrustRootInput(raw); }
  catch (e) { die('HIBA: a bizalmi horgony se nem PEM, se nem ervenyes JSON: ' + e.message); }
  const cv = succ.verifyTrustRootChain(records);
  if (!cv.ok) die('HIBA: a trust-root (lanc) NEM verifikal: ' + cv.problems.join('; '), 1);
  return cv.effective;
}

// ── verify ─────────────────────────────────────────────────────────────────────
// Rekord-tipus szerint agazik: key_succession es key_revocation is ellenorizheto.
if (cmd === 'verify') {
  const [recordPath, anchorPath] = rest;
  if (!recordPath || !anchorPath)
    die('Hasznalat: node axr-key-succession.js verify <rekord.json> <root-pub.pem | trust-root.json | lanc.jsonl>');

  let record;
  try { record = JSON.parse(readFileOrDie(recordPath, 'rekord')); }
  catch (e) { die('HIBA: a rekord ervenytelen JSON: ' + e.message); }
  const anchor = loadAnchorOrDie(anchorPath);

  if (record.record_type === 'key_revocation') {
    const res = succ.verifyKeyRevocation(record, anchor);
    if (res.ok) {
      console.log('Key revocation ERVENYES (root-alairt).');
      console.log('  log_id:     ' + record.log_id);
      console.log('  role:       ' + record.role);
      console.log('  revoked:    ' + record.revoked_fingerprint);
      console.log('  revoked_at: tree_size >= ' + record.revoked_at_tree_size);
      console.log('  reason:     ' + record.reason + '  (issued_at: ' + record.issued_at + ')');
      process.exit(0);
    }
    console.log('Key revocation ERVENYTELEN: ' + res.problems.join('; '));
    process.exit(1);
  }

  const res = succ.verifyKeySuccession(record, anchor);
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

// ── revoke (egykulcsos build) ──────────────────────────────────────────────────
// Kvorum-alairt revokaciohoz a body/sign/assemble ceremonia valo.
if (cmd === 'revoke') {
  const positional = [];
  const flags = {};
  for (let i = 0; i < rest.length; i++) {
    if (rest[i].startsWith('--')) { flags[rest[i].slice(2)] = rest[i + 1]; i++; }
    else positional.push(rest[i]);
  }
  const [rootPrivPath] = positional;
  const usage = 'Hasznalat: node axr-key-succession.js revoke <root-priv.pem> ' +
    '--log-id <id> --role sth|receipt (--revoked <pub.pem> | --revoked-fingerprint sha256:<hex>) ' +
    '--revoked-at <tree_size> [--reason szoveg]';
  if (!rootPrivPath || !flags['log-id'] || !flags.role || !flags['revoked-at']) die(usage);
  if (!flags.revoked && !flags['revoked-fingerprint']) die(usage);
  const rootPriv = readFileOrDie(rootPrivPath, 'root privat kulcs');
  const revokedFp = flags['revoked-fingerprint'] ||
    succ.keyFingerprint(readFileOrDie(flags.revoked, 'revokalando publikus kulcs'));
  let record;
  try {
    record = succ.buildKeyRevocation({
      log_id: flags['log-id'], role: flags.role,
      revoked_fingerprint: revokedFp,
      revoked_at_tree_size: Number(flags['revoked-at']),
      reason: flags.reason
    }, rootPriv);
  } catch (e) { die('HIBA: ' + e.message); }
  // onellenorzes kiiras elott
  const rootPub = crypto.createPublicKey(crypto.createPrivateKey(rootPriv))
    .export({ type: 'spki', format: 'pem' });
  const chk = succ.verifyKeyRevocation(record, rootPub);
  if (!chk.ok) die('HIBA: a felepitett revokacio nem verifikal: ' + chk.problems.join('; '), 1);
  process.stdout.write(JSON.stringify(record) + '\n');
  process.exit(0);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Kvorum-ceremonia: body -> sign (alaironkent, kulon gepeken) -> assemble
// ═══════════════════════════════════════════════════════════════════════════════
// A kezzel gyartott kanonikus JSON es az alairas-fesules garantalt hibaforras
// (self-lockout) - ezert mindharom lepes parancs, onellenorzessel.

// ── body: alairatlan rekord-torzs eloallitasa ──────────────────────────────────
if (cmd === 'body') {
  const kind = rest[0];
  const positional = [];
  const flags = {};
  for (let i = 1; i < rest.length; i++) {
    if (rest[i].startsWith('--')) { flags[rest[i].slice(2)] = rest[i + 1]; i++; }
    else positional.push(rest[i]);
  }
  if (kind === 'succession') {
    const usage = 'Hasznalat: node axr-key-succession.js body succession --log-id <id> --role sth|receipt ' +
      '(--predecessor <pub.pem> | --predecessor-fingerprint sha256:<hex>) --successor <pub.pem> ' +
      '--effective-from <tree_size> [--reason szoveg]';
    if (!flags['log-id'] || !flags.role || !flags.successor || !flags['effective-from']) die(usage);
    if (!flags.predecessor && !flags['predecessor-fingerprint']) die(usage);
    let body;
    try {
      body = succ.buildKeySuccessionBody({
        log_id: flags['log-id'], role: flags.role,
        predecessor_fingerprint: flags['predecessor-fingerprint'] ||
          succ.keyFingerprint(readFileOrDie(flags.predecessor, 'predecessor publikus kulcs')),
        successor_public_key: readFileOrDie(flags.successor, 'successor publikus kulcs'),
        effective_from_tree_size: Number(flags['effective-from']),
        reason: flags.reason
      });
    } catch (e) { die('HIBA: ' + e.message); }
    process.stdout.write(JSON.stringify(body) + '\n');
    process.exit(0);
  }
  if (kind === 'revocation') {
    const usage = 'Hasznalat: node axr-key-succession.js body revocation --log-id <id> --role sth|receipt ' +
      '(--revoked <pub.pem> | --revoked-fingerprint sha256:<hex>) --revoked-at <tree_size> [--reason szoveg]';
    if (!flags['log-id'] || !flags.role || !flags['revoked-at']) die(usage);
    if (!flags.revoked && !flags['revoked-fingerprint']) die(usage);
    let body;
    try {
      body = succ.buildKeyRevocationBody({
        log_id: flags['log-id'], role: flags.role,
        revoked_fingerprint: flags['revoked-fingerprint'] ||
          succ.keyFingerprint(readFileOrDie(flags.revoked, 'revokalando publikus kulcs')),
        revoked_at_tree_size: Number(flags['revoked-at']),
        reason: flags.reason
      });
    } catch (e) { die('HIBA: ' + e.message); }
    process.stdout.write(JSON.stringify(body) + '\n');
    process.exit(0);
  }
  if (kind === 'root-successor') {
    // utod trust-root torzse: az elod fajl lehet rekord vagy lanc (az utolso
    // elem az elod); a leiro JSON: { providers, logs, root_keys | root_public_key, threshold }
    const [predPath, descPath] = positional;
    if (!predPath || !descPath)
      die('Hasznalat: node axr-key-succession.js body root-successor <elod-tr.json|lanc.jsonl> <leiro.json>');
    let predRecords, desc;
    try { predRecords = succ.parseTrustRootInput(readFileOrDie(predPath, 'elod trust-root')); }
    catch (e) { die('HIBA: az elod trust-root ervenytelen: ' + e.message); }
    try { desc = JSON.parse(readFileOrDie(descPath, 'leiro JSON')); }
    catch (e) { die('HIBA: a leiro ervenytelen JSON: ' + e.message); }
    const predecessor = predRecords[predRecords.length - 1];
    let body;
    try {
      body = succ.buildTrustRootBody(desc);
      if (!body.root_keys) {
        if (!desc.root_public_key) die('HIBA: a leiroban root_keys+threshold VAGY root_public_key kell');
        body.root_public_key = desc.root_public_key;
      }
      body.predecessor_trust_root_hash = require('./axr-core').sha256(predecessor);
    } catch (e) { die('HIBA: ' + e.message); }
    process.stdout.write(JSON.stringify(body) + '\n');
    process.exit(0);
  }
  die('Hasznalat: node axr-key-succession.js body <succession|revocation|root-successor> ...');
}

// ── sign: egy alairo reszalairasa egy body folott ──────────────────────────────
if (cmd === 'sign') {
  const [bodyPath, privPath] = rest;
  if (!bodyPath || !privPath)
    die('Hasznalat: node axr-key-succession.js sign <body.json> <alairo-priv.pem>');
  let body;
  try { body = JSON.parse(readFileOrDie(bodyPath, 'body')); }
  catch (e) { die('HIBA: a body ervenytelen JSON: ' + e.message); }
  if (body.signature !== undefined || body.signatures !== undefined)
    die('HIBA: a body mar tartalmaz alairast - a sign alairatlan torzset var');
  let part;
  try { part = succ.signQuorumPart(body, readFileOrDie(privPath, 'alairo privat kulcs')); }
  catch (e) { die('HIBA: ' + e.message); }
  process.stdout.write(JSON.stringify(part) + '\n');
  process.exit(0);
}

// ── assemble: reszalairasok osszefesulese + (opcionalis) kvorum-ellenorzes ─────
if (cmd === 'assemble') {
  const positional = [];
  const flags = {};
  for (let i = 0; i < rest.length; i++) {
    if (rest[i].startsWith('--')) { flags[rest[i].slice(2)] = rest[i + 1]; i++; }
    else positional.push(rest[i]);
  }
  const [bodyPath, ...partPaths] = positional;
  if (!bodyPath || !partPaths.length)
    die('Hasznalat: node axr-key-succession.js assemble <body.json> <part1.json> [part2.json ...] [--verify <root-pub.pem|trust-root.json|lanc.jsonl>]');
  let body;
  try { body = JSON.parse(readFileOrDie(bodyPath, 'body')); }
  catch (e) { die('HIBA: a body ervenytelen JSON: ' + e.message); }
  const parts = partPaths.map(p => {
    try { return JSON.parse(readFileOrDie(p, 'reszalairas (' + p + ')')); }
    catch (e) { return die('HIBA: a reszalairas ervenytelen JSON (' + p + '): ' + e.message); }
  });
  let record;
  try { record = succ.assembleQuorum(body, parts); }
  catch (e) { die('HIBA: ' + e.message); }
  if (flags.verify) {
    // a teljes ellenorzes a rekord-tipus szerint - igy az assemble nem ad ki
    // olyan rekordot, amit a fogyasztok ugyis elutasitananak
    const anchor = loadAnchorOrDie(flags.verify);
    const res = record.record_type === 'key_revocation'
      ? succ.verifyKeyRevocation(record, anchor)
      : record.record_type === 'key_succession'
        ? succ.verifyKeySuccession(record, anchor)
        : { ok: false, problems: ['assemble --verify: ismeretlen record_type: ' + record.record_type] };
    if (!res.ok) die('HIBA: az osszefesult rekord NEM verifikal: ' + res.problems.join('; '), 1);
    console.error('assemble: a rekord a megadott horgonnyal ERVENYES (' + record.signatures.length + ' alairas).');
  } else {
    console.error('assemble: FIGYELEM - horgony nelkul nem ellenorzott (add meg: --verify <horgony>).');
  }
  process.stdout.write(JSON.stringify(record) + '\n');
  process.exit(0);
}

// ═══════════════════════════════════════════════════════════════════════════════
// 0.7 - control log kezeles: add / verify / status
// ═══════════════════════════════════════════════════════════════════════════════
if (cmd === 'control') {
  const sub = rest[0];
  const control = require('./axr-control');

  // control add <control.jsonl> <rekord.json> --trust-root <horgony> [--log-id id]
  // Append ELOTT teljes verify (self-lockout vedelem: ervenytelen rekord nem
  // kerul a logba, kulonben a sidecar/fogyasztok elbuknanak rajta).
  if (sub === 'add') {
    const positional = [];
    const flags = {};
    for (let i = 1; i < rest.length; i++) {
      if (rest[i].startsWith('--')) { flags[rest[i].slice(2)] = rest[i + 1]; i++; }
      else positional.push(rest[i]);
    }
    const [controlPath, recordPath] = positional;
    if (!controlPath || !recordPath || !flags['trust-root'])
      die('Hasznalat: node axr-key-succession.js control add <control.jsonl> <rekord.json> --trust-root <horgony> [--log-id id]');
    let record;
    try { record = JSON.parse(readFileOrDie(recordPath, 'rekord')); }
    catch (e) { die('HIBA: a rekord ervenytelen JSON: ' + e.message); }
    const anchor = loadAnchorOrDie(flags['trust-root']);
    const chk = control.verifyControlRecord(record, anchor, flags['log-id']);
    if (!chk.ok) die('HIBA: a rekord NEM verifikal - nem fuzheto a control loghoz: ' + chk.problems.join('; '), 1);
    fs.appendFileSync(controlPath, JSON.stringify(record) + '\n');
    console.error('control add: a(z) ' + record.record_type + ' rekord hozzafuzve (' + controlPath + ').');
    process.exit(0);
  }

  // control verify <control.jsonl> <horgony> [--log-id id]  (offline lint)
  if (sub === 'verify') {
    const positional = [];
    const flags = {};
    for (let i = 1; i < rest.length; i++) {
      if (rest[i].startsWith('--')) { flags[rest[i].slice(2)] = rest[i + 1]; i++; }
      else positional.push(rest[i]);
    }
    const [controlPath, anchorPath] = positional;
    if (!controlPath || !anchorPath)
      die('Hasznalat: node axr-key-succession.js control verify <control.jsonl> <root-pub.pem|trust-root.json|lanc.jsonl> [--log-id id]');
    const records = readJsonlOrDie(controlPath);
    const anchor = loadAnchorOrDie(anchorPath);
    const res = control.verifyControlLog(records, anchor, flags['log-id']);
    if (res.ok) {
      console.log('Control log ERVENYES: ' + records.length + ' rekord, mind root-autorizalt.');
      console.log('  control_root_hash: ' + control.controlRoot(records));
      process.exit(0);
    }
    console.log('Control log ERVENYTELEN:');
    for (const p of res.problems) console.log('  ' + p);
    process.exit(1);
  }

  // control status <control.jsonl> <horgony> --log-id id [--at <tree_size>]
  // Az adott fa-meretnel ervenyes aktiv kulcsok role-onkent.
  if (sub === 'status') {
    const positional = [];
    const flags = {};
    for (let i = 1; i < rest.length; i++) {
      if (rest[i].startsWith('--')) { flags[rest[i].slice(2)] = rest[i + 1]; i++; }
      else positional.push(rest[i]);
    }
    const [controlPath, anchorPath] = positional;
    if (!controlPath || !anchorPath || !flags['log-id'])
      die('Hasznalat: node axr-key-succession.js control status <control.jsonl> <horgony> --log-id <id> [--at <tree_size>]');
    const records = readJsonlOrDie(controlPath);
    const anchor = loadAnchorOrDie(anchorPath);
    // a loadAnchorOrDie lanc eseten mar az effektiv (egyetlen) trust-root
    // objektumot adja; nyers PEM-bol nincs genesis -> status nem ertelmezheto
    const trObj = (typeof anchor === 'string' || !anchor || anchor.record_type !== 'trust_root') ? null : anchor;
    if (!trObj) die('HIBA: a control status kibovitett trust-root horgonyt igenyel (genesis-kulcsokkal), nem nyers PEM-et.');
    const at = flags.at != null ? Number(flags.at) : Number.MAX_SAFE_INTEGER;
    const res = control.verifyControlLog(records, anchor, flags['log-id']);
    if (!res.ok) { console.log('FIGYELEM: a control log nem teljesen ervenyes - status a valid rekordokbol:'); for (const p of res.problems) console.log('  ' + p); }
    console.log('Aktiv kulcsok @ tree_size=' + (flags.at != null ? at : 'max') + ' (log: ' + flags['log-id'] + '):');
    for (const role of ['sth', 'receipt']) {
      const genesisPem = succ.genesisKey(trObj, flags['log-id'], role);
      if (!genesisPem) { console.log('  ' + role + ': (nincs genesis ehhez a role-hoz)'); continue; }
      const tl = succ.buildKeyTimeline(genesisPem, res.valid, role, anchor,
        res.valid.filter(r => r.record_type === 'key_revocation'));
      const e = succ.keyAtTreeSize(tl.timeline, at);
      const revoked = e && e.revoked_from != null && at >= e.revoked_from;
      console.log('  ' + role + ': ' + (e ? e.fingerprint : '(nincs)') +
        (e && !e.authorized ? ' [NEM AUTORIZALT]' : '') + (revoked ? ' [REVOKALT @' + e.revoked_from + ']' : ''));
    }
    process.exit(0);
  }

  die('Hasznalat: node axr-key-succession.js control <add|verify|status> ...');
}

die('Hasznalat: node axr-key-succession.js <build|verify|fingerprint|revoke|body|sign|assemble|control> ...');
