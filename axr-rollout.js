#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════════════
// AXR - Production rollout tooling (bootstrap + preflight)
// ═══════════════════════════════════════════════════════════════════════════════
// Egy futo 0.2-0.4 pilot (egy operator-kulcs, TOFU-pinning) atallitasa a 0.5-0.7
// root-horgonyzott modra OPERATIV kockazat. A legnagyobb veszely a SELF-LOCKOUT:
// rossz trust-root / nem-egyezo genesis eseten a fogyasztok minden STH-t
// elutasitanak. Ez az eszkoz ezt celozza:
//
//   bootstrap - trust-root ceremonia a MAR HASZNALT operator-kulcsokbol. A
//               genesis kulcs a tenylegesen alairo kulcs, igy a meglevo STH-k
//               NEM urulnek el (a genesis from=0-tol ervenyes). Single VAGY
//               kvorum (M-of-N) root. Onellenorzes kiiras elott.
//
//   preflight - GO / NO-GO readiness-check egy deploymentre ELES kapcsolas ELOTT.
//               A KONFIG-hibakat fogja, amik a verifier-futas elott rejtve
//               maradnanak: a genesis sth-kulcs tenyleg alairja-e a legkorabbi
//               STH-t (kulonben minden STH bukik), kvorum-eppseg, anchor-backend
//               fuggetlenseg, monitor-jelenlet, control-konzisztencia. Vegul
//               lefuttatja a hiteles axr-verify.js-t es beagyazza a verdiktjet.
//               Exit 0 = GO, 1 = NO-GO (blocker talalat), 2 = rossz hasznalat.
//
// OSZINTE HATAR: a preflight nem garantal helyes uzemeltetest - a tipikus
// self-lockout es N3/N4 buktatokat fogja meg, es minden talalathoz remediaciot
// ad. A bizalmi dontes (kit teszel a root-keszletbe, hany aláíró) a tied.
//
// Nulla kulso fuggoseg - csak a Node beepitett moduljai + a kozos AXR-modulok.
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const core = require('./axr-core');
const succ = require('./axr-succession');
const control = require('./axr-control');

function die(msg, code) { console.error(msg); process.exit(code == null ? 2 : code); }
function readFileOrDie(p, label) {
  try { return fs.readFileSync(p, 'utf8'); } catch (e) { die('HIBA: a(z) ' + label + ' nem olvashato: ' + e.message); }
}
function readJsonl(p) {
  if (!p || !fs.existsSync(p)) return [];
  return fs.readFileSync(p, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
}
function pubFromPriv(privPem) {
  return crypto.createPublicKey(crypto.createPrivateKey(privPem)).export({ type: 'spki', format: 'pem' });
}
function csv(v) { return String(v || '').split(',').map(x => x.trim()).filter(Boolean); }

// ═══════════════════════════════════════════════════════════════════════════════
// bootstrap - trust-root ceremonia a meglevo operator-kulcsokbol
// ═══════════════════════════════════════════════════════════════════════════════
function cmdBootstrap(flags) {
  if (!flags['log-id'] || !flags['sth-pub'])
    die('Hasznalat: node axr-rollout.js bootstrap --log-id <id> --sth-pub <pem> [--receipt-pub <pem>]\n' +
        '         single root:  --root-priv <pem>\n' +
        '         kvorum root:   --root-keys k1.pem,k2.pem,k3.pem --threshold M --root-privs p1.pem,p2.pem\n' +
        '         [--out trust-root.json] [--empty-control control.jsonl]');
  const sthPub = readFileOrDie(flags['sth-pub'], 'sth genesis publikus kulcs');
  const receiptPub = flags['receipt-pub'] ? readFileOrDie(flags['receipt-pub'], 'receipt genesis publikus kulcs') : null;
  const logs = [{ log_id: flags['log-id'], genesis: { sth: sthPub, receipt: receiptPub } }];

  let tr;
  if (flags['root-keys'] || flags['root-privs'] || flags.threshold) {
    // kvorum mod
    const keyPaths = csv(flags['root-keys']);
    const privPaths = csv(flags['root-privs']);
    const threshold = Number(flags.threshold);
    if (!privPaths.length) die('HIBA: kvorum bootstraphoz --root-privs kotelezo (az alairo privat kulcsok)');
    const privs = privPaths.map(p => readFileOrDie(p, 'root privat kulcs (' + p + ')'));
    // ha --root-keys nincs megadva, a privatokbol szarmaztatjuk a publikus keszletet
    const rootKeys = keyPaths.length ? keyPaths.map(p => readFileOrDie(p, 'root publikus kulcs (' + p + ')'))
      : privs.map(pubFromPriv);
    if (!Number.isInteger(threshold) || threshold < 1 || threshold > rootKeys.length)
      die('HIBA: --threshold 1..' + rootKeys.length + ' kell legyen');
    try { tr = succ.buildQuorumTrustRoot({ providers: [], logs, root_keys: rootKeys, threshold }, privs); }
    catch (e) { die('HIBA: ' + e.message); }
  } else {
    // single mod
    if (!flags['root-priv']) die('HIBA: single bootstraphoz --root-priv kotelezo');
    const rootPriv = readFileOrDie(flags['root-priv'], 'root privat kulcs');
    const rootPub = flags['root-pub'] ? readFileOrDie(flags['root-pub'], 'root publikus kulcs') : pubFromPriv(rootPriv);
    try { tr = succ.buildTrustRoot({ providers: [], logs }, rootPriv, rootPub); }
    catch (e) { die('HIBA: ' + e.message); }
  }

  // onellenorzes kiiras elott (mint a tobbi CLI)
  const chk = succ.verifyTrustRoot(tr);
  if (!chk.ok) die('HIBA: a felepitett trust-root nem verifikal: ' + chk.problems.join('; '), 1);

  if (flags['empty-control'] && !fs.existsSync(flags['empty-control']))
    fs.writeFileSync(flags['empty-control'], '');
  const out = JSON.stringify(tr) + '\n';
  if (flags.out) { fs.writeFileSync(flags.out, out); console.error('Trust-root kiirva: ' + flags.out + ' (mod: ' + succ.trustRootMode(tr).mode + ')'); }
  else process.stdout.write(out);
  process.exit(0);
}

// ═══════════════════════════════════════════════════════════════════════════════
// preflight - GO / NO-GO readiness (KONFIG-hibak, mielott elesitesz)
// ═══════════════════════════════════════════════════════════════════════════════
// -> { go, findings: [{ level: 'blocker'|'warning'|'ok', code, message, fix }] }
function preflight(inputs) {
  const findings = [];
  const F = (level, code, message, fix) => findings.push({ level, code, message, fix: fix || null });

  // 0. A hiteles verifier futtatasa KOTELEZO az eles GO-hoz (Meridian-review):
  // a config-checkek smoke-tesztek; a teljes idovonal-fedest (rotalt log,
  // hianyzo succession/control) CSAK az axr-verify.js bizonyitja. Nelkule
  // a preflight nem adhat GO-t.
  if (!inputs.runVerifier)
    F('blocker', 'NO_VERIFIER', 'A preflight nem certifikalhat GO-t a hiteles verifier futtatasa nelkul.',
      'Add meg a --key-t (es a kormanyzati inputokat: --successions / --control / --revocations), hogy az axr-verify.js lefuthasson a teljes fedesert.');

  // 1. trust-root verifikal-e (lanc-kepes)
  const trRecords = inputs.trustRoot;
  if (!trRecords) {
    F('warning', 'NO_TRUST_ROOT', 'Nincs trust-root - a fogyasztok TOFU-pinning modban maradnak (0.3/0.4 viselkedes).',
      'Adj meg --trust-root-ot, ha a root-horgonyzott (0.5+) modot akarod elesiteni.');
    return finishPreflight(findings, inputs);
  }
  const cv = succ.verifyTrustRootChain(Array.isArray(trRecords) ? trRecords : [trRecords]);
  if (!cv.ok) {
    F('blocker', 'TRUST_ROOT_INVALID', 'A trust-root (lanc) NEM verifikal: ' + cv.problems.join('; '),
      'Epitsd ujra a trust-rootot (axr-rollout bootstrap) ervenyes root-kulcsokkal/kvorummal.');
    return finishPreflight(findings, inputs);
  }
  const effective = cv.effective;
  const mode = succ.trustRootMode(effective);
  F('ok', 'TRUST_ROOT_OK', 'A trust-root verifikal (mod: ' + mode.mode + (mode.mode === 'quorum' ? ', ' + mode.threshold + '-of-' + mode.keys.length : '') + ').');

  // 2. kvorum-eppseg: a threshold ne legyen 1 tobb-kulcsos keszletnel veletlenul,
  //    es ne legyen N=1 "kvorum" (az alig jobb a single-nel) - figyelmeztetes
  if (mode.mode === 'quorum') {
    if (mode.threshold === 1 && mode.keys.length > 1)
      F('warning', 'QUORUM_THRESHOLD_1', 'A kvorum threshold=1 tobb kulcs mellett - barmely EGYETLEN kulcs autorizal.',
        'Emeld a threshold-ot (ajanlott 2-of-3), ha valodi tobb-fel kontrollt akarsz.');
    if (mode.keys.length === 1)
      F('warning', 'QUORUM_SINGLE_KEY', 'A "kvorum" egyetlen kulcsbol all (1-of-1) - nincs tobb-fel vedelem.',
        'Vegy fel tobb fuggetlen root-kulcsot kulon orzessel.');
  }

  // 3. genesis deklaralva-e a loghoz + EGYEZIK-E a tenyleges alairoval (a kulcs!)
  const logId = inputs.logId || (inputs.sths[0] && inputs.sths[0].log_id);
  if (!logId)
    F('blocker', 'NO_LOG_ID', 'A log_id nem allapithato meg (nincs --log-id es nincs STH).',
      'Add meg a --log-id-t, vagy biztosits legalabb egy STH-t.');
  const genesisSth = logId ? succ.genesisKey(effective, logId, 'sth') : null;
  if (logId && !genesisSth)
    F('blocker', 'NO_GENESIS', 'A trust-root nem deklaral sth-genesis kulcsot ehhez a loghoz (' + logId + ').',
      'Bootstrapeld a trust-rootot a megfelelo --log-id-vel es --sth-pub-bal.');

  // EZ a kulcs self-lockout-fogo ellenorzes: a deklaralt genesis sth-kulcs
  // tenyleg alairja-e az STH-kat? A LEGKORABBIT mindenkepp kell. Ha kesobbi
  // STH-k MAS kulccsal keszultek (rotacio), a legkorabbi-egyezes ONMAGABAN
  // FELREVEZETO (Meridian-review): a self-lockout-mentesseg ilyenkor csak a
  // teljes verifier-idovonalbol bizonyitott - ezert ott csak figyelmeztetunk,
  // es a kotelezo verifier (0. pont) a hiteles kapu.
  if (genesisSth && inputs.sths.length) {
    const sorted = inputs.sths.slice().sort((a, b) => a.tree_size - b.tree_size);
    const earliest = sorted[0];
    const signsBy = (sth) => { try { return core.verifyReceipt(sth, genesisSth); } catch (e) { return false; } };
    if (!signsBy(earliest)) {
      F('blocker', 'GENESIS_MISMATCH', 'A deklaralt genesis sth-kulcs NEM irja ala a legkorabbi STH-t (tree_size=' + earliest.tree_size + ').',
        'A genesisnek a legkorabbi STH-t TENYLEGESEN alairo operator-kulcsnak kell lennie. Bootstrapeld a genesist az eredeti aláíró kulccsal (rotalt pilotnal NEM a jelenlegi, hanem a LEGKORABBI signer).');
    } else if (sorted.every(signsBy)) {
      F('ok', 'GENESIS_SIGNS', 'A genesis sth-kulcs MINDEN STH-t alairja (tree_size 1..' + sorted[sorted.length - 1].tree_size + ') - rotacio nelkuli log, nincs self-lockout.');
    } else {
      F('warning', 'ROTATION_PRESENT', 'A genesis alairja a legkorabbi STH-t, de kesobbi STH-k MAS kulccsal keszultek (rotacio van a logban). A self-lockout-mentesseg ilyenkor NEM bizonyitott a genesis-checkbol.',
        'Add meg a teljes kormanyzati inputot (--successions / --control / trust-root lanc), es a kotelezo verifier-futas bizonyitja a teljes idovonal-fedest. Reszleges STH-fajl is felrevezeto lehet - a teljes sth.jsonl-t add be.');
    }
  } else if (genesisSth && !inputs.sths.length) {
    F('warning', 'NO_STH_SAMPLE', 'Nincs STH a bemenetben - a genesis-egyezes nem ellenorizheto.',
      'Add be a tenyleges sth.jsonl-t a preflighthoz.');
  }

  // 4. receipt-genesis (ha van receipt es genesis-receipt): alairja-e a legkorabbi receiptet
  const genesisRec = logId ? succ.genesisKey(effective, logId, 'receipt') : null;
  const firstReceipt = (inputs.receipts || []).find(r => ['step', 'workflow', 'identity'].includes(r.receipt_type));
  if (genesisRec && firstReceipt) {
    let signs = false;
    try { signs = core.verifyReceipt(firstReceipt, genesisRec); } catch (e) { signs = false; }
    if (!signs)
      F('warning', 'RECEIPT_GENESIS_MISMATCH', 'A genesis receipt-kulcs nem irja ala a legkorabbi receiptet - rotacio elott ez self-lockout lehet.',
        'Ellenorizd, hogy a receipt-genesis a tenylegesen alairo kulcs, vagy adj receipt-role successiont a control logba.');
  }

  // 5. anchor-backend fuggetlenseg (N3): a 'local' nem fuggetlen bizonyitek
  const backends = [...new Set((inputs.anchors || []).map(a => a.backend).filter(Boolean))];
  if (!backends.length)
    F('warning', 'NO_ANCHOR', 'Nincs anchor-rekord - a horgonyzas latens vedelme nem aktiv.',
      'Futtass anchor sidecart legalabb egy backenddel.');
  else if (backends.length === 1 && backends[0] === 'local')
    F('warning', 'LOCAL_ANCHOR_ONLY', 'Csak "local" anchor - ez NEM operatortol fuggetlen bizonyitek (N3).',
      'Adj hozza opentimestamps (vagy mas fuggetlen) backendet az eles horgonyzashoz.');
  else
    F('ok', 'ANCHOR_OK', 'Operatortol fuggetlen anchor-backend jelen: ' + backends.join(', ') + '.');

  // 6. control-commitment konzisztencia (ha az STH-k commitolnak)
  const committing = (inputs.sths || []).filter(s => typeof s.control_root_hash === 'string');
  if (committing.length) {
    if (!inputs.control)
      F('blocker', 'CONTROL_WITHHELD', 'Az STH-k control-keszletre commitolnak, de nincs control log atadva.',
        'Add meg a --control control.jsonl-t, kulonben a fogyasztok CONTROL_WITHHELD-del bukjak.');
    else {
      let mismatch = false;
      for (const sth of committing) { const chk = control.checkSthCommitment(sth, inputs.control); if (!chk.ok) mismatch = true; }
      if (mismatch) F('blocker', 'CONTROL_MISMATCH', 'A control-commitment nem egyezik a megadott control loggal.',
        'Biztositsd, hogy a publikalt control.jsonl pontosan az, amire az STH-k commitoltak.');
      else F('ok', 'CONTROL_OK', committing.length + ' STH commitol; a control log egyezik.');
    }
  }

  // 7. monitor-jelenlet (N4) + pinned-genesis egyezes. Ha a monitor mar
  // pinnelt egy genesis trust-rootot, az MAS hash eseten eles pollnal
  // TRUST_ROOT_CHANGED-et (fail-closed) dob -> operativ lockout (Meridian-review).
  const ms = inputs.monitorState;
  if (!ms)
    F('warning', 'NO_MONITOR', 'Nem talaltam monitor-journalt - az anti-tampering garanciak csak fut, fuggetlen monitorral valodiak (N4).',
      'Allits be egy monitort az operatortol fuggetlen felkent (--monitor-state a journal utjaval ellenorizheto).');
  else if (ms.trust_root_genesis_hash) {
    const head = Array.isArray(trRecords) ? trRecords[0] : trRecords;
    const suppliedGenesisHash = core.sha256(head);
    if (ms.trust_root_genesis_hash !== suppliedGenesisHash)
      F('blocker', 'MONITOR_GENESIS_MISMATCH', 'A monitor-journalban pinnelt genesis trust-root ELTER a most megadottol - eles pollnal TRUST_ROOT_CHANGED (fail-closed) lesz.',
        'Hasznald ugyanazt a genesis trust-rootot, amit a monitor mar pinnelt; trust-root rotacional a LANC fejet (genesis) tartsd valtozatlanul, vagy tudatos migracional uritsd a monitor-journalt.');
    else
      F('ok', 'MONITOR_GENESIS_OK', 'A monitor-journalban pinnelt genesis egyezik a megadott trust-root lanc fejevel.');
  }

  return finishPreflight(findings, inputs);
}

// a hiteles verifier-verdikt beagyazasa (ha futtathato)
function finishPreflight(findings, inputs) {
  if (inputs.runVerifier && typeof inputs.runVerifier === 'function') {
    const v = inputs.runVerifier();
    if (v.ok) findings.push({ level: 'ok', code: 'VERIFIER_PASS', message: 'Az axr-verify.js elfogadja a logot (exit 0).', fix: null });
    else findings.push({ level: 'blocker', code: 'VERIFIER_FAIL', message: 'Az axr-verify.js ELUTASITJA a logot (exit ' + v.code + ').',
      fix: 'Futtasd kozvetlenul az axr-verify.js-t a reszletekert; eles kapcsolas elott a lognak verifikalnia kell.' });
  }
  const go = !findings.some(f => f.level === 'blocker');
  return { go, findings };
}

module.exports = { preflight };

// ── CLI ──────────────────────────────────────────────────────────────────────
if (require.main === module) {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  const rest = argv.slice(1);
  const positional = [];
  const flags = {};
  for (let i = 0; i < rest.length; i++) {
    if (rest[i].startsWith('--')) { flags[rest[i].slice(2)] = rest[i + 1]; i++; }
    else positional.push(rest[i]);
  }

  if (cmd === 'bootstrap') { cmdBootstrap(flags); }

  else if (cmd === 'preflight') {
    const [receiptsPath, sthPath, anchorsPath] = positional;
    if (!receiptsPath)
      die('Hasznalat: node axr-rollout.js preflight <receipts.jsonl> [sth.jsonl] [anchors.jsonl]\n' +
          '            --trust-root <json> [--control <jsonl>] [--log-id <id>] [--monitor-state <json>] [--key <pem>]');
    const trustRoot = flags['trust-root'] ? succ.parseTrustRootInput(fs.readFileSync(flags['trust-root'], 'utf8')) : null;
    const keyPath = flags.key;
    const runVerifier = keyPath ? () => {
      const args = [path.join(__dirname, 'axr-verify.js'), receiptsPath, keyPath];
      if (sthPath) args.push(sthPath);
      if (anchorsPath) args.push(anchorsPath);
      for (const f of ['trust-root', 'control', 'successions', 'revocations', 'log-id'])
        if (flags[f]) args.push('--' + f, flags[f]);
      try { execFileSync('node', args, { stdio: 'pipe' }); return { code: 0, ok: true }; }
      catch (e) { return { code: e.status == null ? -1 : e.status, ok: false }; }
    } : null;

    const res = preflight({
      receipts: readJsonl(receiptsPath),
      sths: readJsonl(sthPath).filter(r => r.record_type === 'sth'),
      anchors: readJsonl(anchorsPath).filter(r => r.record_type === 'anchor'),
      trustRoot,
      control: flags.control ? readJsonl(flags.control) : null,
      logId: flags['log-id'],
      monitorState: (flags['monitor-state'] && fs.existsSync(flags['monitor-state']))
        ? JSON.parse(fs.readFileSync(flags['monitor-state'], 'utf8')) : null,
      runVerifier
    });

    console.log('─'.repeat(72));
    console.log('AXR PREFLIGHT — ' + (res.go ? 'GO ✓' : 'NO-GO ✗'));
    console.log('─'.repeat(72));
    const icon = { blocker: '✗ BLOCKER', warning: '! WARNING', ok: '✓ ok      ' };
    for (const f of res.findings) {
      console.log(`  ${icon[f.level]}  [${f.code}] ${f.message}`);
      if (f.fix && f.level !== 'ok') console.log(`              → ${f.fix}`);
    }
    console.log('─'.repeat(72));
    const blockers = res.findings.filter(f => f.level === 'blocker').length;
    const warns = res.findings.filter(f => f.level === 'warning').length;
    console.log(res.go
      ? `GO: nincs blocker (${warns} figyelmeztetes - nezd at oket eles kapcsolas elott).`
      : `NO-GO: ${blockers} blocker - javitsd oket, kulonben a rollout self-lockoutot vagy elutasitott logot okoz.`);
    process.exit(res.go ? 0 : 1);
  }

  else {
    die('Hasznalat: node axr-rollout.js <bootstrap|preflight> ...');
  }
}
