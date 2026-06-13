// ═══════════════════════════════════════════════════════════════════════════════
// AXR 0.3 Stage B - horgonyzo sidecar (anchoring sidecar)
// ═══════════════════════════════════════════════════════════════════════════════
// A sidecar az n8n-en KIVUL fut (cron vagy hosszu eletu worker), es a kozos,
// bind-mountolt receipts.jsonl-bol dolgozik. A foglalasi hot path NEM fugg tole:
// egy backend-kimaradas a receiptet "fuggoben" allapotba teszi, sosem torik el a
// receiptet magat (spec 9.6, N3).
//
// Mit csinal egy futasra:
//   1. Beolvassa a receipteket append-sorrendben; a leveleket (step/workflow/
//      identity) kiszuri.
//   2. Beolvassa a meglevo STH-lancot; megnezi, hany level van mar lefedve.
//   3. Ha van uj level: RFC 6962 Merkle-gyokeret szamol a TELJES jelenlegi fara,
//      kiad egy uj Signed Tree Head-et (alairva, az elozo STH-hoz lancolva).
//   4. A gyokeret beadja minden konfiguralt backendnek (local / opentimestamps),
//      es az anchor-rekordokat hozzafuzi az anchors.jsonl-hez.
//   5. Visszairja az anchor_ref-et minden ujonnan lefedett receiptbe - ez az
//      EGYETLEN modositas a receipts.jsonl-en, es az alairas szempontjabol
//      semleges (spec 4.1: az anchor_ref nincs benne az alairasban).
//
// Idempotens: ha nincs uj level, nem keletkezik uj STH. A mar lehorgonyzott
// receiptek megtartjak az eredeti anchor_ref-juket (a sajat STH-jukra mutatva).
//
// Hasznalat (CLI):
//   node axr-anchor.js <receipts.jsonl> <private-key.pem> \
//        [--sth sth.jsonl] [--anchors anchors.jsonl] \
//        [--backend local|opentimestamps] [--log-id axr:agent:v1] \
//        [--succession key-succession.json]   (0.5: rotacio utan az utod
//                                              elso STH-jaba agyazodik be)
//
// Nulla kulso fuggoseg - csak a Node beepitett moduljai + a kozos axr-core.js.
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');
const https = require('https');
const crypto = require('crypto');
const axr = require('./axr-core');
const succession = require('./axr-succession');
const control = require('./axr-control');

// A control-trust-root horgony betoltese fajlbol (PEM, egy rekord, vagy lanc).
// A control.resolveAnchor a tipust feloldja; itt csak beolvasunk + parse-olunk.
function succession_control_loadAnchor(p) {
  const raw = fs.readFileSync(p, 'utf8');
  if (raw.trimStart().startsWith('-----BEGIN')) return raw;
  return succession.parseTrustRootInput(raw);
}

const LEAF_TYPES = ['step', 'workflow', 'identity'];

// ── JSONL I/O ──────────────────────────────────────────────────────────────────
function readJsonl(p) {
  if (!p || !fs.existsSync(p)) return [];
  return fs.readFileSync(p, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
}
function appendJsonl(p, objs) {
  if (!objs.length) return;
  fs.appendFileSync(p, objs.map(o => JSON.stringify(o)).join('\n') + '\n');
}
// Atomi feluliras: temp fajlba irunk, majd atnevezzuk - igy egy megszakadt futas
// sem hagy felig irt receipts.jsonl-t.
function atomicWriteJsonl(p, objs) {
  const tmp = p + '.tmp';
  fs.writeFileSync(tmp, objs.map(o => JSON.stringify(o)).join('\n') + '\n');
  fs.renameSync(tmp, p);
}
function sibling(p, name) { return path.join(path.dirname(path.resolve(p)), name); }

// ── anchor-state.json cache (inkrementalis Merkle allapot) ─────────────────────
function readJson(p) {
  if (!p || !fs.existsSync(p)) return null;
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch (e) { return null; }
}
function atomicWriteJson(p, obj) {
  const tmp = p + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(obj));
  fs.renameSync(tmp, p);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Backendek - mindegyik egy STH-gyokeret kap, es egy anchor-rekordot ad vissza
// ═══════════════════════════════════════════════════════════════════════════════

// local: determinisztikus, offline backend teszthez es fejlesztoi futtatashoz.
// NEM nyujt fuggetlen bizonyitekot (ugyanaz az operator szamolja) - csak a
// sidecar gepezetenek ellenorzesere valo.
function anchorLocal(rootHash, treeSize, now) {
  return {
    axr_version: '0.3', record_type: 'anchor', sth_root_hash: rootHash, tree_size: treeSize,
    backend: 'local',
    backend_entry: { proof: axr.sha256('axr-local-anchor:' + rootHash) },
    retrieved_at: now()
  };
}

// OpenTimestamps publikus naptarai (digest-bekuldes).
const OTS_CALENDARS = [
  'https://a.pool.opentimestamps.org',
  'https://b.pool.opentimestamps.org',
  'https://alice.btc.calendar.opentimestamps.org'
];

// Egy SHA-256 digest bekuldese egy naptarnak (POST {cal}/digest, nyers 32 bajt).
function postDigest(calendarUrl, digest, timeoutMs) {
  return new Promise((resolve, reject) => {
    const u = new URL(calendarUrl.replace(/\/$/, '') + '/digest');
    const req = https.request({
      hostname: u.hostname, path: u.pathname, method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'Accept': 'application/vnd.opentimestamps.v1',
        'Content-Length': digest.length,
        'User-Agent': 'axr-anchor/0.3'
      }, timeout: timeoutMs || 8000
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) resolve(Buffer.concat(chunks));
        else reject(new Error('HTTP ' + res.statusCode));
      });
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.write(digest);
    req.end();
  });
}

// opentimestamps: a gyokeret (mint SHA-256 digestet) beadja a publikus naptaraknak.
// A naptarak nyugtaja egy reszleges idobelyeg; a Bitcoin-attesztacio a kovetkezo
// blokkokkal erik be. A vegleges .ots proof osszeallitasa/upgrade-je a standard
// ots eszkozzel tortenik a rogzitett valaszokbol - a sidecar a digest commitmentet
// es a naptar-valaszokat rogziti. Halozat nelkul "pending_offline" allapotot ir,
// ami kesobb (halozatban) ujrafuttatva bekuldheto.
async function anchorOpenTimestamps(rootHash, treeSize, now, timeoutMs) {
  const digest = Buffer.from(rootHash.replace(/^sha256:/, ''), 'hex');
  const responses = [];
  for (const cal of OTS_CALENDARS) {
    try {
      const r = await postDigest(cal, digest, timeoutMs);
      responses.push({ calendar: cal, status: 'submitted', response_b64: r.toString('base64') });
    } catch (e) {
      responses.push({ calendar: cal, status: 'unreachable', error: e.message });
    }
  }
  const submitted = responses.some(r => r.status === 'submitted');
  return {
    axr_version: '0.3', record_type: 'anchor', sth_root_hash: rootHash, tree_size: treeSize,
    backend: 'opentimestamps',
    backend_entry: {
      digest: rootHash,
      calendars: responses,
      ots_status: submitted ? 'submitted_pending_bitcoin' : 'pending_offline',
      note: submitted
        ? 'A naptarak megkaptak a digestet; a Bitcoin-attesztacio a kovetkezo blokkokkal erik be. A vegleges .ots proof az ots CLI-vel allithato ossze/upgrade-elheto a rogzitett valaszokbol.'
        : 'Nincs halozat - a digest keszen all a bekuldesre. Futtasd ujra halozati eleressel, vagy add be kezzel az ots CLI-vel ezt a digestet.'
    },
    retrieved_at: now()
  };
}

async function submitBackend(name, rootHash, treeSize, now, opts) {
  if (name === 'local') return anchorLocal(rootHash, treeSize, now);
  if (name === 'opentimestamps') return anchorOpenTimestamps(rootHash, treeSize, now, opts.timeoutMs);
  throw new Error('ismeretlen backend: ' + name);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Fo horgonyzo lepes
// ═══════════════════════════════════════════════════════════════════════════════
// opts:
//   receiptsPath  (kotelezo)  - az append-only receipts.jsonl
//   privateKeyPem (kotelezo)  - az STH-t alairo Ed25519 kulcs (PEM)
//   sthPath       (opc.)      - default: <dir>/sth.jsonl
//   anchorsPath   (opc.)      - default: <dir>/anchors.jsonl
//   backends      (opc.)      - default: ['local']
//   logId         (opc.)      - default: 'axr:default:v1'
//   now           (opc.)      - () => ISO timestamp (tesztelhetoseghez)
//   timeoutMs     (opc.)      - backend HTTP timeout
//   succession    (opc.)      - root-alairt key_succession rekord (role=sth);
//                               az utod kulcs ELSO STH-jaba agyazodik be
//                               (embedded_succession, 0.5). Nelkule az STH a
//                               mai (0.3) formaban keszul - nulla valtozas.
//   controlPath   (opc., 0.7) - control.jsonl (governance-rekordok). Ha adott,
//                               az STH commitol ra (control_root_hash +
//                               control_size). controlTrustRoot(Path) kotelezo:
//                               a sidecar commit elott teljes kripto-verifyt fut.
//   controlTrustRoot / controlTrustRootPath (opc., 0.7) - a control-rekordok
//                               root-horgonya (PEM | trust-root | lanc).
async function runAnchor(opts) {
  if (!opts.receiptsPath) throw new Error('receiptsPath kotelezo');
  if (!opts.privateKeyPem) throw new Error('privateKeyPem kotelezo');
  const receiptsPath = opts.receiptsPath;
  const sthPath = opts.sthPath || sibling(receiptsPath, 'sth.jsonl');
  const anchorsPath = opts.anchorsPath || sibling(receiptsPath, 'anchors.jsonl');
  const backends = opts.backends && opts.backends.length ? opts.backends : ['local'];
  const logId = opts.logId || 'axr:default:v1';
  const now = opts.now || (() => new Date().toISOString());

  const receipts = readJsonl(receiptsPath);
  const leafIdx = [];
  receipts.forEach((r, i) => { if (LEAF_TYPES.includes(r.receipt_type)) leafIdx.push(i); });
  const leaves = leafIdx.map(i => receipts[i]);
  const leafHashes = leaves.map(axr.leafHash);

  const sths = readJsonl(sthPath);
  const lastSth = sths.length ? sths[sths.length - 1] : null;
  const coveredSize = lastSth ? lastSth.tree_size : 0;

  if (leaves.length <= coveredSize) {
    return { created: false, reason: 'nincs uj level a horgonyzashoz', treeSize: leaves.length, coveredSize };
  }

  // 1. Uj STH a teljes jelenlegi fa felett, az elozohoz lancolva.
  // A gyokeret INKREMENTALISAN szamoljuk az anchor-state.json cache-bol: csak az
  // uj leveleket fuzzuk a tarolt peakekhez (O(uj_levelek + log n)), nem szamoljuk
  // ujra a teljes fat. Ha a cache hianyzik / serult / nem illik a jelenlegi
  // levelszamhoz (pl. tobb levelet allit, mint amennyi van), NULLAROL ujraepitunk
  // - a vegeredmeny byte-azonos a from-scratch gyokerrel (mmrRoot == merkleRootFromLeaves).
  const statePath = opts.statePath || sibling(receiptsPath, 'anchor-state.json');
  const cache = readJson(statePath);
  let peaks = [];
  let from = 0;
  if (cache && axr.mmrValid(cache.peaks, cache.leaf_count) && cache.leaf_count <= leafHashes.length) {
    peaks = cache.peaks;
    from = cache.leaf_count;
  }
  for (let i = from; i < leafHashes.length; i++) peaks = axr.mmrAppend(peaks, leafHashes[i]);
  const rootHash = axr.mmrRoot(peaks);

  // 1/b. Kulcs-utodlas beagyazasa (0.5): ha a hivo atad egy root-alairt
  // key_succession rekordot, az az UTOD kulcs ELSO STH-jaba kerul be
  // (embedded_succession). A signablePart es a chainHash nem vagja le, tehat
  // az alairas ES a lanc is fedi -> a beagyazott rekord manipulacio-evidens.
  // Withholding-fix: a monitor a rotaciot magabol a logbol latja, nem kell a
  // successiont kulon csatornan terjeszteni. Idempotens: ha barmely korabbi
  // STH mar beagyazta ezt az utod-kulcsot, nem ismeteljuk - az STH a mai
  // (0.3) formaban keszul. Succession nelkul a viselkedes byte-ra a regi.
  let embedSuccession = null;
  if (opts.succession) {
    const sc = opts.succession;
    if (sc.record_type !== 'key_succession' || sc.role !== 'sth')
      throw new Error('succession: csak role=sth key_succession rekord agyazhato STH-ba');
    // a succession ehhez a loghoz tartozik? (idegen log ervenyes rekordja sem agyazhato be)
    if (sc.log_id !== logId)
      throw new Error('succession: a rekord log_id-ja (' + sc.log_id + ') nem egyezik a sidecar logjaval (' + logId + ')');
    // a succession tenyleg az STH-t alairo kulcsot autorizalja?
    const signerPem = crypto.createPublicKey(opts.privateKeyPem)
      .export({ type: 'spki', format: 'pem' });
    if (sc.successor_fingerprint !== succession.keyFingerprint(signerPem))
      throw new Error('succession: a successor_fingerprint nem az STH-t alairo kulcse');
    // hatar-szabaly: az utod csak tree_size >= effective_from_tree_size-tol irhat ala
    if (leaves.length < sc.effective_from_tree_size)
      throw new Error('succession: a fa-meret (' + leaves.length + ') az effective_from_tree_size (' +
        sc.effective_from_tree_size + ') hatara elott van - az utod meg nem irhat ala');
    const already = sths.some(t => t.embedded_succession &&
      t.embedded_succession.successor_fingerprint === sc.successor_fingerprint);
    if (!already) embedSuccession = sc;
    // 0.8 DEPRECATION: a control log (0.7) az elsodleges governance-csatorna.
    // Az embedded_succession atmeneti; ha a hivo control logot is hasznal,
    // jelezzuk, hogy a successiont inkabb a control logba tegye. Eltavolitasi
    // horizont: 1.0 (lasd AXR-SPEC-0.8 par. P3).
    if (embedSuccession && opts.controlPath)
      console.error('FIGYELEM (deprecated): az embedded_succession atmeneti - control log mellett a key_succession-t a control logba (witness_set/key_succession csatorna) erdemes tenni. Eltavolitas: 1.0.');
  }

  // 1/c. Control-log commitment (0.7): ha a hivo atad egy controlPath-t, az STH
  // body-ja commitol a governance-keszletre (control_root_hash + control_size).
  // Meridian-kikotes: commit ELOTT MINDEN control-rekord teljes kripto-verifyt
  // kap (root/kvorum-alairas, log_id, tipus-allowlist) - ervenytelen
  // governance-anyag NEM anchorolhato (kulonben minden fogyasztot fail-closed
  // allapotba kenyszeritene: DoS/self-lockout). Ehhez controlTrustRoot is kell.
  // controlPath nelkul az STH valtozatlan (0.3/0.5) - nulla regresszio.
  let controlCommit = null;
  if (opts.controlPath) {
    const controlRecords = readJsonl(opts.controlPath);
    if (!opts.controlTrustRoot && !opts.controlTrustRootPath)
      throw new Error('control: a controlPath mellett controlTrustRoot(Path) kotelezo (commit elotti verify-hoz)');
    const controlAnchor = opts.controlTrustRoot ||
      succession_control_loadAnchor(opts.controlTrustRootPath);
    const chk = control.verifyControlLog(controlRecords, controlAnchor, logId);
    if (!chk.ok)
      throw new Error('control: a control log NEM verifikal (ervenytelen governance-anyag nem anchorolhato):\n  ' + chk.problems.join('\n  '));
    controlCommit = { control_root_hash: control.controlRoot(controlRecords), control_size: controlRecords.length };
  }

  const sthBody = {
    axr_version: (embedSuccession || controlCommit) ? '0.5' : '0.3', record_type: 'sth', log_id: logId,
    tree_size: leaves.length, root_hash: rootHash, timestamp: now(),
    previous_sth_hash: lastSth ? axr.chainHash(lastSth) : null
  };
  if (embedSuccession) sthBody.embedded_succession = embedSuccession;
  if (controlCommit) {
    sthBody.control_root_hash = controlCommit.control_root_hash;
    sthBody.control_size = controlCommit.control_size;
  }
  sthBody.signature = axr.signReceipt(sthBody, opts.privateKeyPem);
  appendJsonl(sthPath, [sthBody]);
  // a frissitett inkrementalis allapot perzisztalasa (atomian)
  atomicWriteJson(statePath, { leaf_count: leaves.length, peaks, root_hash: rootHash, updated_at: now() });

  // 2. Backendek - a gyoker kulso lehorgonyzasa
  const anchorRecords = [];
  for (const bn of backends) anchorRecords.push(await submitBackend(bn, rootHash, leaves.length, now, opts));
  appendJsonl(anchorsPath, anchorRecords);

  // 3. anchor_ref visszairas - csak az eddig le NEM horgonyzott levelekre
  let anchored = 0;
  leafIdx.forEach((ri, li) => {
    if (!receipts[ri].anchor_ref) {
      receipts[ri].anchor_ref = {
        sth_root_hash: rootHash,
        tree_size: leaves.length,
        leaf_index: li,
        inclusion_proof: axr.inclusionProof(li, leafHashes),
        backends: backends.slice()
      };
      anchored++;
    }
  });
  if (anchored) atomicWriteJsonl(receiptsPath, receipts);

  return {
    created: true, treeSize: leaves.length, anchored,
    sth: sthBody, anchorRecords, sthPath, anchorsPath
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// upgrade - a fuggoben levo OpenTimestamps horgonyok naptari megerositese
// ═══════════════════════════════════════════════════════════════════════════════
// A horgonyzaskor a naptarak csak egy reszleges idobelyeget adnak; a Bitcoin-
// attesztacio a kovetkezo blokkokkal erik be. Az 'upgrade' kesobb ujra lekerdezi
// a naptarakat: ismeri-e mar a commitmentet (GET /timestamp/<digest>). Ha igen,
// a naptar-bejegyzes statuszat 'confirmed'-re emeli es rogziti az upgrade valaszt.
//
// HATAR (oszinten): ez a naptari ismertseget bizonyitja - a vegleges Bitcoin-blokk
// PoW ellenorzes a standard 'ots verify' CLI dolga a rogzitett valaszokbol. Az
// AXR ezt szandekosan delegalja, hogy ne kelljen Bitcoin SPV-t ujraimplementalni.
function getTimestamp(calendarUrl, digestHex, timeoutMs) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(calendarUrl.replace(/\/$/, '') + '/timestamp/' + digestHex); }
    catch (e) { return resolve({ status: 'bad_url', error: e.message }); }
    const req = https.request({
      hostname: u.hostname, path: u.pathname, method: 'GET',
      headers: { 'Accept': 'application/vnd.opentimestamps.v1', 'User-Agent': 'axr-anchor/0.4' },
      timeout: timeoutMs || 8000
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        if (res.statusCode === 200) resolve({ status: 'confirmed', response_b64: Buffer.concat(chunks).toString('base64') });
        else if (res.statusCode === 404) resolve({ status: 'pending' });
        else resolve({ status: 'http_' + res.statusCode });
      });
    });
    req.on('error', e => resolve({ status: 'unreachable', error: e.message }));
    req.on('timeout', () => { req.destroy(); resolve({ status: 'timeout' }); });
    req.end();
  });
}

async function runUpgrade(opts) {
  const anchorsPath = opts.anchorsPath;
  if (!anchorsPath) throw new Error('anchorsPath kotelezo');
  const now = opts.now || (() => new Date().toISOString());
  const anchors = readJsonl(anchorsPath);
  let changed = 0, confirmedCals = 0, stillPending = 0;

  for (const a of anchors) {
    if (a.backend !== 'opentimestamps') continue;
    const be = a.backend_entry || {};
    if (be.ots_status === 'confirmed') continue;
    const digestHex = String(a.sth_root_hash).replace(/^sha256:/, '');
    const cals = Array.isArray(be.calendars) ? be.calendars : [];
    let anyConfirmed = false, anyPending = false;
    for (const c of cals) {
      const r = await getTimestamp(c.calendar, digestHex, opts.timeoutMs || 8000);
      if (r.status === 'confirmed') {
        c.status = 'confirmed';
        c.upgrade_response_b64 = r.response_b64;
        c.upgraded_at = now();
        anyConfirmed = true; confirmedCals++;
      } else if (r.status === 'pending') {
        anyPending = true; stillPending++;
      } else {
        c.last_upgrade_attempt = { at: now(), status: r.status, error: r.error || null };
      }
    }
    const newStatus = anyConfirmed ? 'confirmed' : (anyPending ? 'submitted_pending_bitcoin' : be.ots_status);
    if (newStatus !== be.ots_status || anyConfirmed) {
      be.ots_status = newStatus;
      be.upgraded_at = now();
      a.backend_entry = be;
      changed++;
    }
  }

  if (changed) atomicWriteJsonl(anchorsPath, anchors);
  return { changed, confirmedCals, stillPending, total: anchors.length };
}

module.exports = { runAnchor, runUpgrade, getTimestamp, OTS_CALENDARS, LEAF_TYPES };

// ── CLI ──────────────────────────────────────────────────────────────────────
if (require.main === module) {
  const rawArgs = process.argv.slice(2);

  // 'upgrade' alparancs: a fuggo OTS horgonyok naptari megerositese.
  //   node axr-anchor.js upgrade <anchors.jsonl>
  if (rawArgs[0] === 'upgrade') {
    const anchorsPath = rawArgs[1];
    if (!anchorsPath) {
      console.error('Hasznalat: node axr-anchor.js upgrade <anchors.jsonl>');
      process.exit(2);
    }
    runUpgrade({ anchorsPath }).then(res => {
      console.log(`Upgrade kesz: ${res.changed} anchor-rekord frissult ` +
        `(${res.confirmedCals} naptar megerositve, ${res.stillPending} meg fuggoben, ${res.total} osszesen).`);
      console.log(`A vegleges Bitcoin-attesztacio ellenorzese: 'ots verify' a rogzitett naptar-valaszokon.`);
      process.exit(0);
    }).catch(e => { console.error('HIBA:', e.message); process.exit(1); });
    return;
  }

  const args = rawArgs;
  const positional = [];
  const flags = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith('--')) { flags[args[i].slice(2)] = args[i + 1]; i++; }
    else positional.push(args[i]);
  }
  const [receiptsPath, keyPath] = positional;
  if (!receiptsPath || !keyPath) {
    console.error('Hasznalat: node axr-anchor.js <receipts.jsonl> <sth-private-key.pem> ' +
      '[--sth sth.jsonl] [--anchors anchors.jsonl] [--backend local|opentimestamps] [--log-id axr:agent:v1] ' +
      '[--succession key-succession.json] ' +
      '[--control control.jsonl --control-trust-root trust-root.json]\n' +
      '       node axr-anchor.js upgrade <anchors.jsonl>');
    process.exit(2);
  }
  const privateKeyPem = fs.readFileSync(keyPath, 'utf8');
  runAnchor({
    receiptsPath, privateKeyPem,
    sthPath: flags.sth, anchorsPath: flags.anchors,
    backends: flags.backend ? [flags.backend] : ['local'],
    logId: flags['log-id'],
    succession: flags.succession ? JSON.parse(fs.readFileSync(flags.succession, 'utf8')) : undefined,
    controlPath: flags.control,
    controlTrustRootPath: flags['control-trust-root']
  }).then(res => {
    if (!res.created) {
      console.log(`Nincs teendo: ${res.reason} (fa-meret ${res.treeSize}, lefedve ${res.coveredSize}).`);
    } else {
      console.log(`Uj STH: tree_size=${res.treeSize}, root=${res.sth.root_hash.slice(0, 24)}...`);
      console.log(`Lehorgonyzott uj receiptek: ${res.anchored}`);
      for (const a of res.anchorRecords) {
        const extra = a.backend === 'opentimestamps' ? ` [${a.backend_entry.ots_status}]` : '';
        console.log(`  backend: ${a.backend}${extra}`);
      }
      console.log(`STH:     ${res.sthPath}`);
      console.log(`Anchors: ${res.anchorsPath}`);
    }
    process.exit(0);
  }).catch(e => { console.error('HIBA:', e.message); process.exit(1); });
}
