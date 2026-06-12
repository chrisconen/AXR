// ═══════════════════════════════════════════════════════════════════════════════
// AXR 0.3 Stage D - fuggetlen Monitor
// ═══════════════════════════════════════════════════════════════════════════════
// A horgonyzas (Stage B) onmagaban LATENS vedelem: a Signed Tree Head-ek leteznek,
// de csak akkor ernek valamit, ha valaki - az operatortol FUGGETLEN fel - tenylegesen
// figyeli oket. Ez a Monitor. A verifier egy logot EGY idopillanatban ellenoriz
// (belso konzisztencia); a Monitor IDOBEN es NEZETEK KOZOTT: sajat, megorzott
// naplot (journal) vezet, es riaszt, ha az uj nezet ellentmond a korabbinak.
//
// Mit fog el (spec 7.5, G5/G6):
//   - EQUIVOCATION: ugyanahhoz a tree_size-hoz mas root jelenik meg, mint amit a
//     monitor korabban naplozott -> az operator ket kulonbozo fat mutatott
//   - TRUNCATION:   a log zsugorodott (a jelenlegi max tree_size < naplozott max)
//   - NON_APPEND_ONLY: az egymast koveto STH-k kozott a consistency proof megbukik
//   - ROOT_MISMATCH: egy STH olyan rootot allit, ami nem egyezik a tenyleges
//     receiptek Merkle-gyokerevel (ha a monitor megkapja a recepteket)
//   - BAD_SIGNATURE: egy STH alairasa ervenytelen a rogzitett kulcsra
//
// 0.5 - key succession (opcionalis trust-root mellett):
//   A 0.3 monitor EGY kulcsot pinnel (TOFU), igy a legitim rotacio is
//   megkulonboztethetetlen a csendes kulcscseretol. Trust-roottal a monitor a
//   FUGGETLEN root-kulcsban bizik: a genesis kulcs a trust-rootbol jon, minden
//   tovabbi kulcsot root-alairt key_succession autorizal. Az STH-kba beagyazott
//   successiont (embedded_succession) a monitor ELOBB a root-kulccsal
//   verifikalja, es csak utana hasznalja az uj kulcsot STH-ellenorzesre.
//   Uj kodok: KEY_ROTATED_AUTHORIZED (megjegyzes - a rotacio root-autorizalt)
//   es KEY_CHANGED_UNAUTHORIZED (SERTES - kulcsvaltas root-autorizacio nelkul).
//   Trust-root NELKUL minden a regi: TOFU-pinning, KEY_CHANGED.
//
// Ket parancs:
//   poll    - egy operator STH-fajljanak figyelese, a journal frissitese
//   compare - ket monitor journaljanak osszevetese (split-view bizonyitas)
//
// Hasznalat:
//   node axr-monitor.js poll <sth.jsonl> <public-key.pem> \
//        [--state monitor-state.json] [--receipts receipts.jsonl] \
//        [--anchors anchors.jsonl] [--log-id axr:agent:v1] \
//        [--trust-root trust-root.json] [--successions successions.jsonl] \
//        [--ocsf-out <fajl|->] [--webhook <url>]
//        [--webhook-token <token> | --webhook-token-file <fajl> | AXR_WEBHOOK_TOKEN env]
//   node axr-monitor.js compare <monitor-state-A.json> <monitor-state-B.json>
//
// OCSF / webhook (0.5+): --ocsf-out a sertesek/eletciklus-jelzesek OCSF
// Detection Finding alakjat irja (JSONL; '-' = stdout); --webhook ugyanezt
// POST-olja egy generikus HTTP(S) vegpontra (axr-ocsf.js, axr-webhook.js).
// Mindketto best-effort export: a kilepesi kodot a detekcio hatarozza meg.
//
// Nulla kulso fuggoseg - csak a Node beepitett moduljai + a kozos axr-core.js.
// Kilepesi kod: 0 ha minden konzisztens, 1 ha sertest talal, 2 ha rossz hasznalat.
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const axr = require('./axr-core');
const succ = require('./axr-succession');

const LEAF_TYPES = ['step', 'workflow', 'identity'];
const MONITOR_VERSION = '0.5';

function readJsonl(p) {
  if (!p || !fs.existsSync(p)) return [];
  return fs.readFileSync(p, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
}
function keyFingerprint(pem) {
  // a PEM-bol kinyert nyers kulcs-bajtok hash-e (whitespace-fuggetlen)
  const body = String(pem).replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  return 'sha256:' + crypto.createHash('sha256').update(body, 'utf8').digest('hex');
}
function loadState(statePath) {
  if (statePath && fs.existsSync(statePath)) return JSON.parse(fs.readFileSync(statePath, 'utf8'));
  return null;
}
function sibling(p, name) { return path.join(path.dirname(path.resolve(p)), name); }
function saveState(statePath, state) {
  if (!statePath) return;
  const tmp = statePath + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(state, null, 2) + '\n');
  fs.renameSync(tmp, statePath);
}

// ═══════════════════════════════════════════════════════════════════════════════
// poll - egy operator STH-fajljanak figyelese
// ═══════════════════════════════════════════════════════════════════════════════
// opts:
//   sthPath      (kotelezo) - az operator sth.jsonl-je
//   publicKeyPem (kotelezo) - a rogzitett (pinned) operator-kulcs
//   statePath    (opc.)     - a monitor sajat journalja (default: <dir>/monitor-state.json)
//   receiptsPath (opc.)     - ha megvan, a monitor ujraszamolja a rootokat es a
//                             consistency proofokat (legerosebb ellenorzes)
//   anchorsPath  (opc.)     - kulso anchor cross-check (offline: jelzes)
//   logId        (opc.)     - elvart log_id (elso futaskor rogzul)
//   now          (opc.)     - () => ISO timestamp (tesztelhetoseghez)
//   trustRoot    (opc.)     - 0.5 trust-root objektum (root-kulcs + genesisek).
//                             Ha megvan, az STH-verify kulcs-idovonal alapu;
//                             nelkule a regi TOFU-pinning viselkedes fut.
//   trustRootPath(opc.)     - mint a trustRoot, fajlbol betoltve
//   successions  (opc.)     - kulso (nem beagyazott) key_succession rekordok
function pollMonitor(opts) {
  if (!opts.sthPath) throw new Error('sthPath kotelezo');
  if (!opts.publicKeyPem) throw new Error('publicKeyPem kotelezo');
  const statePath = opts.statePath || sibling(opts.sthPath, 'monitor-state.json');
  const now = opts.now || (() => new Date().toISOString());
  const fp = keyFingerprint(opts.publicKeyPem);
  // 0.6: a --trust-root lehet egyetlen rekord (0.5) VAGY lanc (genesis +
  // utod-rootok, JSONL/tomb). A lanc-feloldas a 3/b blokkban tortenik; itt
  // csak normalizalunk rekordlistava.
  const trustRootRecords = (opts.trustRoot || opts.trustRootPath)
    ? succ.parseTrustRootInput(opts.trustRoot || fs.readFileSync(opts.trustRootPath, 'utf8'))
    : null;

  const violations = [];
  const notices = [];
  const V = (code, msg) => violations.push({ code, message: msg });
  const N = (msg) => notices.push(msg);

  // 1. journal betoltese / inicializalas + kulcs es log_id rogzitese
  // Trust-root mellett a kulcs-valtas megitelese az idovonal dolga (lasd 3/b),
  // ezert a TOFU-fele KEY_CHANGED itt csak trust-root NELKUL fut - igy a regi
  // (0.3/0.4) viselkedes valtozatlan marad.
  let state = loadState(statePath);
  if (!state) {
    state = { axr_monitor_version: MONITOR_VERSION, log_id: opts.logId || null,
              public_key_fingerprint: fp, witnessed: [] };
  } else {
    if (!trustRootRecords && state.public_key_fingerprint !== fp)
      V('KEY_CHANGED', `a rogzitett operator-kulcs megvaltozott (journal: ${state.public_key_fingerprint.slice(0, 20)}..., most: ${fp.slice(0, 20)}...)`);
    if (opts.logId && state.log_id && state.log_id !== opts.logId)
      V('LOG_ID_CHANGED', `a log_id megvaltozott (journal: ${state.log_id}, most: ${opts.logId})`);
  }

  // 2. STH-k beolvasasa, rendezes tree_size szerint
  const sths = readJsonl(opts.sthPath).filter(r => r.record_type === 'sth').sort((a, b) => a.tree_size - b.tree_size);
  if (!sths.length) {
    // Ures folyam onmagaban nem artatlan: ha a journal mar tanusitott fat,
    // a teljes kiurules a TRUNCATION legszelsosegesebb esete - korabban a
    // korai return a 6-os check ELOTT lefutott, igy ez nema maradt.
    const journalMaxEmpty = state.witnessed.reduce((m, w) => Math.max(m, w.tree_size), 0);
    if (journalMaxEmpty > 0) {
      V('TRUNCATION', `a publikalt STH-folyam KIURULT, mikozben a journal mar tanusitott egy ${journalMaxEmpty} meretu fat - a log eltunt vagy toroltek`);
    } else {
      N('nincs STH a fajlban - nincs mit figyelni');
    }
    saveState(statePath, state);
    return finalize(state, violations, notices);
  }
  if (state.log_id == null) state.log_id = sths[0].log_id || opts.logId || null;

  // 3. (opcionalis) receiptek -> levelhashek a root- es consistency-ellenorzeshez
  const receipts = readJsonl(opts.receiptsPath);
  const leafHashes = receipts.filter(r => LEAF_TYPES.includes(r.receipt_type)).map(axr.leafHash);
  const haveLeaves = leafHashes.length > 0;
  if (!haveLeaves && opts.receiptsPath) N('a receipts.jsonl ures vagy hianyzik - a root/consistency ellenorzes kimarad');

  // 3/b. (0.5, opcionalis) kulcs-idovonal a trust-rootbol + successionokbol.
  // SORREND-INVARIANS: minden succession (beagyazott vagy kulso) ELOBB a pinned
  // root-kulccsal verifikalodik, es csak az ervenyesek epitik az idovonalat -
  // az STH-alairast SOSEM ellenorizzuk olyan kulccsal, amit nem a root autorizalt.
  const currentMax = sths[sths.length - 1].tree_size;
  let timeline = null;
  if (trustRootRecords) {
    // 0.6: lanc-feloldas - a fej onmagaban ervenyes genesis, minden utodot az
    // ELOD kvoruma autorizal; az effektiv root a lanc vege. Egyrekordos
    // bemenetre ez pontosan a 0.5-os verifyTrustRoot viselkedes.
    const cv = succ.verifyTrustRootChain(trustRootRecords);
    if (!cv.ok) {
      // fail-closed: ervenytelen trust-root/lanc mellett semmilyen
      // kulcs-allitast nem fogadunk el - a poll itt veget er, sertessel
      V('TRUST_ROOT_INVALID', 'a trust-root (lanc) NEM verifikal: ' + cv.problems.join('; '));
      saveState(statePath, state);
      return finalize(state, violations, notices);
    }
    // genesis-pin: a journal az ELSO latott lanc-fejet rogziti. Egy tamado
    // sajat, onmagaban konzisztens lancot is gyarthatna - a pin ezt fogja el:
    // mas genesis = TRUST_ROOT_CHANGED, fail-closed.
    const genesisHash = axr.sha256(trustRootRecords[0]);
    if (state.trust_root_genesis_hash && state.trust_root_genesis_hash !== genesisHash) {
      V('TRUST_ROOT_CHANGED', `a pinned genesis trust root MEGVALTOZOTT (journal: ${state.trust_root_genesis_hash.slice(0, 20)}..., most: ${genesisHash.slice(0, 20)}...) - lanc-csere kiserlet`);
      saveState(statePath, state);
      return finalize(state, violations, notices);
    }
    state.trust_root_genesis_hash = genesisHash;
    const trustRoot = cv.effective;
    const effLogId = state.log_id || opts.logId || null;
    const genesisPem = succ.genesisKey(trustRoot, effLogId, 'sth');
    // succession-pool: a beagyazottak + a kulso forrasok, dedup, root-verify
    const pool = [];
    const seenSucc = new Set();
    const addSucc = (s, src) => {
      if (!s || typeof s !== 'object') return;
      const h = axr.sha256(s);
      if (seenSucc.has(h)) return;
      seenSucc.add(h);
      // 0.6: a horgony maga a trust-root objektum - igy az egykulcsos ES a
      // kvorum-modu (root_keys+threshold) root is ugyanazon az uton verifikal
      const v = succ.verifyKeySuccession(s, trustRoot);
      if (!v.ok) {
        V('KEY_CHANGED_UNAUTHORIZED', `${src}: a succession NEM verifikal a root-kulcsra: ${v.problems.join('; ')}`);
        return;
      }
      if (s.role !== 'sth') { N(`${src}: role=${s.role} succession - az sth-idovonalhoz nem hasznalhato`); return; }
      if (s.log_id !== effLogId) {
        V('KEY_CHANGED_UNAUTHORIZED', `${src}: a succession idegen loghoz tartozik (${s.log_id} != ${effLogId})`);
        return;
      }
      pool.push(s);
    };
    for (const sth of sths)
      if (sth.embedded_succession) addSucc(sth.embedded_succession, `STH (tree_size=${sth.tree_size}) embedded_succession`);
    for (const s of (opts.successions || [])) addSucc(s, 'kulso succession');

    if (!genesisPem) {
      // degradalt mod: nincs root-horgonyzott genesis ehhez a loghoz -> a regi
      // TOFU-pinning marad (fail-closed: minden kulcsvaltas kritikus)
      N(`DEGRADED: a trust-root nem tartalmaz sth-genesis kulcsot ehhez a loghoz (${effLogId}) - TOFU-pinning mod`);
      if (state.public_key_fingerprint !== fp)
        V('KEY_CHANGED', `a rogzitett operator-kulcs megvaltozott (journal: ${state.public_key_fingerprint.slice(0, 20)}..., most: ${fp.slice(0, 20)}...)`);
    } else {
      const tl = succ.buildKeyTimeline(genesisPem, pool, 'sth', trustRoot);
      for (const p of tl.problems) N('succession-idovonal: ' + p);
      timeline = tl.timeline;
      // journal-bovites: a succession-lanc kanonikus hash-e (compare-hez).
      // Determinisztikus TELJES rendezes: effective_from, majd kanonikus hash
      // tie-break - igy ket monitor ugyanarra a halmazra ugyanazt a lanc-hash-t
      // szamolja a beerkezesi sorrendtol fuggetlenul (NEXUS-review talalata:
      // azonos effective_from-nal a sorrend instabil volt -> vakriasztas).
      pool.sort((a, b) => (a.effective_from_tree_size - b.effective_from_tree_size) ||
        axr.sha256(a).localeCompare(axr.sha256(b)));
      state.succession_chain_hash = pool.length ? axr.sha256(pool) : null;
      // autorizalt rotaciok jelzese (mar hatalyba lepett szegmensek)
      for (const e of timeline) {
        if (e.from_tree_size > 0 && e.authorized && currentMax >= e.from_tree_size)
          N(`KEY_ROTATED_AUTHORIZED: root-autorizalt kulcsvaltas effective_from=${e.from_tree_size} (uj kulcs: ${e.fingerprint.slice(0, 20)}...)`);
      }
      // a monitor pinned kulcsa valtozott? az idovonal donti el, hogy legitim-e
      if (state.public_key_fingerprint !== fp) {
        const entry = timeline.find(e => e.fingerprint === fp);
        if (entry && entry.authorized) {
          N(`KEY_ROTATED_AUTHORIZED: a pinned kulcs az idovonal szerint autorizalt utodra valtott (${fp.slice(0, 20)}...)`);
          state.public_key_fingerprint = fp;
        } else {
          V('KEY_CHANGED_UNAUTHORIZED', `a pinned operator-kulcs megvaltozott, es az uj kulcs NINCS root-autorizalt idovonalon (journal: ${state.public_key_fingerprint.slice(0, 20)}..., most: ${fp.slice(0, 20)}...)`);
        }
      }
    }
  }

  // 4. minden STH: alairas, (ha van) root-egyezes, equivocation a journal ellen
  // Idovonal mellett minden STH-t a SAJAT tree_size-anal ervenyes kulccsal
  // ellenorzunk (keyAtTreeSize); a genesis from=0, igy mindig van talalat.
  const journalBySize = {};
  for (const w of state.witnessed) journalBySize[w.tree_size] = w;

  for (const sth of sths) {
    if (timeline) {
      const e = succ.keyAtTreeSize(timeline, sth.tree_size);
      if (!axr.verifyReceipt(sth, e.pem))
        V('BAD_SIGNATURE', `STH (tree_size=${sth.tree_size}): ERVENYTELEN ALAIRAS az idovonal szerinti kulcsra (${e.fingerprint.slice(0, 20)}...) - lehetseges be-nem-jelentett kulcscsere`);
      else if (!e.authorized)
        V('KEY_CHANGED_UNAUTHORIZED', `STH (tree_size=${sth.tree_size}): a(z) ${e.fingerprint.slice(0, 20)}... kulcs irta ala, de a kulcsvaltas NEM autorizalt (tort/utkozo succession-lanc)`);
    } else if (!axr.verifyReceipt(sth, opts.publicKeyPem))
      V('BAD_SIGNATURE', `STH (tree_size=${sth.tree_size}): ERVENYTELEN ALAIRAS`);

    if (haveLeaves && sth.tree_size <= leafHashes.length) {
      const recomputed = axr.merkleRootFromLeaves(leafHashes.slice(0, sth.tree_size));
      if (recomputed !== sth.root_hash)
        V('ROOT_MISMATCH', `STH (tree_size=${sth.tree_size}): a root_hash nem egyezik a tenyleges receiptek Merkle-gyokerevel`);
    }

    const seen = journalBySize[sth.tree_size];
    if (seen && seen.root_hash !== sth.root_hash)
      V('EQUIVOCATION', `STH (tree_size=${sth.tree_size}): a root elter a korabban naplozottol ` +
        `(journal: ${seen.root_hash.slice(0, 20)}..., most: ${sth.root_hash.slice(0, 20)}...) - az operator ket kulonbozo fat mutatott`);
  }

  // 5. append-only az egymast koveto STH-k kozott (consistency proof, ha vannak levelek)
  for (let i = 1; i < sths.length; i++) {
    if (sths[i].previous_sth_hash !== axr.chainHash(sths[i - 1]))
      N(`STH-lanc: a(z) ${sths[i].tree_size}-meretu STH previous_sth_hash-e nem az elozore mutat (a fajlbeli sorrend hianyos lehet)`);
    if (haveLeaves && sths[i].tree_size <= leafHashes.length) {
      const m = sths[i - 1].tree_size, n = sths[i].tree_size;
      const proof = axr.consistencyProof(m, leafHashes.slice(0, n));
      if (!axr.verifyConsistency(m, n, sths[i - 1].root_hash, sths[i].root_hash, proof))
        V('NON_APPEND_ONLY', `STH ${m} -> ${n}: a consistency proof MEGBUKOTT - az ujabb fa nem az append-only bovitese a reginek`);
    } else if (!haveLeaves) {
      N(`STH ${sths[i - 1].tree_size} -> ${sths[i].tree_size}: a consistency receptek nelkul nem ellenorizheto (CONSISTENCY_UNVERIFIED)`);
    }
  }

  // 6. truncation: a jelenlegi max kisebb, mint a naplozott max
  const journalMax = state.witnessed.reduce((m, w) => Math.max(m, w.tree_size), 0);
  if (currentMax < journalMax)
    V('TRUNCATION', `a log zsugorodott: a jelenlegi max tree_size (${currentMax}) kisebb a korabban naplozottnal (${journalMax}) - rekordokat tavolitottak el`);

  // 7. cross-poll consistency: a naplozott legnagyobb fa -> a jelenlegi legnagyobb fa
  const journalTop = state.witnessed.slice().sort((a, b) => b.tree_size - a.tree_size)[0];
  if (journalTop && haveLeaves && currentMax <= leafHashes.length && journalTop.tree_size < currentMax) {
    const proof = axr.consistencyProof(journalTop.tree_size, leafHashes.slice(0, currentMax));
    if (!axr.verifyConsistency(journalTop.tree_size, currentMax, journalTop.root_hash, sths[sths.length - 1].root_hash, proof))
      V('NON_APPEND_ONLY', `cross-poll ${journalTop.tree_size} -> ${currentMax}: a korabban latott fa NEM prefixe a mostaninak - a multat atirtak`);
  }

  // 8. kulso anchor cross-check (offline: explicit jelzes)
  const anchors = readJsonl(opts.anchorsPath).filter(a => a.record_type === 'anchor');
  for (const a of anchors) {
    N(`ANCHOR_UNVERIFIED: ${a.backend} anchor (tree_size=${a.tree_size}) - offline mod, a backend nincs fuggetlenul lekerdezve`);
  }

  // 9. journal frissitese: minden uj (meg nem latott) tree_size felvetele
  for (const sth of sths) {
    if (!journalBySize[sth.tree_size]) {
      state.witnessed.push({
        tree_size: sth.tree_size, root_hash: sth.root_hash, sth_hash: axr.chainHash(sth),
        sth_timestamp: sth.timestamp, first_seen_at: now()
      });
    }
  }
  state.witnessed.sort((a, b) => a.tree_size - b.tree_size);
  // journal-bovites (0.5): a jelenleg aktiv (legnagyobb fanal ervenyes) kulcs
  if (timeline) {
    const active = succ.keyAtTreeSize(timeline, currentMax);
    state.active_key_fingerprint = active ? active.fingerprint : null;
  }
  saveState(statePath, state);

  return finalize(state, violations, notices);
}

function finalize(state, violations, notices) {
  return { ok: violations.length === 0, violations, notices,
           witnessedCount: state.witnessed.length,
           journalMax: state.witnessed.reduce((m, w) => Math.max(m, w.tree_size), 0),
           // export-kontextus (0.5+, OCSF/webhook): a findinghez kell a log
           // azonositoja es az aktiv kulcs - additiv mezok, semmit nem tornek
           logId: state.log_id || null,
           activeKeyFingerprint: state.active_key_fingerprint || state.public_key_fingerprint || null };
}

// ═══════════════════════════════════════════════════════════════════════════════
// compare - ket monitor journaljanak osszevetese (split-view / equivocation bizonyitas)
// ═══════════════════════════════════════════════════════════════════════════════
// Ha ket fuggetlen monitor UGYANAHHOZ a tree_size-hoz KULONBOZO rootot naplozott,
// az bizonyitja, hogy az operator ket eltero fat mutatott a ket monitornak.
function compareJournals(a, b) {
  const conflicts = [];
  const aBySize = {}; for (const w of a.witnessed || []) aBySize[w.tree_size] = w;
  for (const w of b.witnessed || []) {
    const av = aBySize[w.tree_size];
    if (av && av.root_hash !== w.root_hash)
      conflicts.push({ tree_size: w.tree_size, root_a: av.root_hash, root_b: w.root_hash });
  }
  if ((a.log_id || null) !== (b.log_id || null))
    conflicts.push({ log_id_mismatch: true, log_id_a: a.log_id || null, log_id_b: b.log_id || null });
  if ((a.public_key_fingerprint || null) !== (b.public_key_fingerprint || null))
    conflicts.push({ key_mismatch: true });
  // 0.5: divergens succession-lanc = az operator ket monitornak ket kulonbozo
  // kulcs-tortenetet mutatott (csak ha MINDKET journal latott lancot - a regi,
  // 0.3-as journalokban a mezo hianyzik, az nem konfliktus)
  const ca = a.succession_chain_hash || null, cb = b.succession_chain_hash || null;
  if (ca && cb && ca !== cb)
    conflicts.push({ succession_chain_mismatch: true, chain_a: ca, chain_b: cb });
  return { equivocationDetected: conflicts.length > 0, conflicts };
}

module.exports = { pollMonitor, compareJournals, keyFingerprint, LEAF_TYPES };

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

  function printResult(label, res) {
    console.log('-'.repeat(72));
    for (const n of res.notices) console.log(`  [megj] ${n}`);
    if (res.ok) {
      console.log(`${label}: KONZISZTENS. ${res.witnessedCount} STH a journalban (max tree_size=${res.journalMax}).`);
    } else {
      for (const v of res.violations) console.log(`  [SERTES:${v.code}] ${v.message}`);
      console.log(`${label}: SERTES TALALVA (${res.violations.length}). A log atirast/equivocationt mutat.`);
    }
    console.log('-'.repeat(72));
  }

  if (cmd === 'poll') {
    const [sthPath, keyPath] = positional;
    if (!sthPath || !keyPath) {
      console.error('Hasznalat: node axr-monitor.js poll <sth.jsonl> <public-key.pem> [--state monitor-state.json] [--receipts receipts.jsonl] [--anchors anchors.jsonl] [--log-id ...] [--trust-root trust-root.json] [--successions successions.jsonl] [--ocsf-out <fajl|->] [--webhook <url>] [--webhook-token <token> | --webhook-token-file <fajl> | AXR_WEBHOOK_TOKEN env]');
      process.exit(2);
    }
    const publicKeyPem = fs.readFileSync(keyPath, 'utf8');
    const res = pollMonitor({
      sthPath, publicKeyPem, statePath: flags.state,
      receiptsPath: flags.receipts, anchorsPath: flags.anchors, logId: flags['log-id'],
      trustRootPath: flags['trust-root'],
      successions: flags.successions ? readJsonl(flags.successions) : undefined
    });
    printResult('Monitor poll', res);

    // OCSF-export / webhook (0.5+): a detekcio eredmenye (exit code, journal) a
    // hiteles; az export es a kezbesites best-effort, a kilepesi kodot nem
    // valtoztatja. Egy elerheteetlen SIEM nem nemithatja el a monitort.
    if (!flags['ocsf-out'] && !flags.webhook) process.exit(res.ok ? 0 : 1);
    const ocsf = require('./axr-ocsf');
    const findings = ocsf.toDetectionFindings(res, {
      logId: flags['log-id'] || res.logId,
      productVersion: require('./package.json').version
    });
    if (flags['ocsf-out']) {
      const out = findings.map(f => JSON.stringify(f)).join('\n') + (findings.length ? '\n' : '');
      if (flags['ocsf-out'] === '-') process.stdout.write(out);
      else fs.writeFileSync(flags['ocsf-out'], out);
      console.log(`OCSF: ${findings.length} finding -> ${flags['ocsf-out'] === '-' ? 'stdout' : flags['ocsf-out']}`);
    }
    if (flags.webhook && findings.length) {
      // Token-feloldas (Meridian-review nyoman): a CLI-arg lathato a process-
      // listaban es a shell-historyban, ezert fajl es kornyezeti valtozo is
      // tamogatott. Prioritas: --webhook-token > --webhook-token-file >
      // AXR_WEBHOOK_TOKEN env.
      let webhookToken = flags['webhook-token'] || null;
      if (!webhookToken && flags['webhook-token-file'])
        webhookToken = fs.readFileSync(flags['webhook-token-file'], 'utf8').trim();
      if (!webhookToken && process.env.AXR_WEBHOOK_TOKEN)
        webhookToken = process.env.AXR_WEBHOOK_TOKEN;
      if (/^http:/i.test(flags.webhook))
        console.log('Webhook: FIGYELEM - http (titkositatlan) cel: a findingok plaintextben mennek at a halozaton.');
      require('./axr-webhook').deliver(flags.webhook, findings, { token: webhookToken })
        .then(d => {
          if (d.delivered) console.log(`Webhook: kezbesitve (${findings.length} finding, HTTP ${d.status}).`);
          else console.log(`Webhook: KEZBESITES SIKERTELEN (${d.attempts} kiserlet): ${d.error} - a detekcio eredmenye ettol fuggetlenul ervenyes.`);
          process.exit(res.ok ? 0 : 1);
        });
    } else {
      if (flags.webhook) console.log('Webhook: nincs finding, nincs kuldes.');
      process.exit(res.ok ? 0 : 1);
    }
  } else if (cmd === 'compare') {
    const [aPath, bPath] = positional;
    if (!aPath || !bPath) {
      console.error('Hasznalat: node axr-monitor.js compare <monitor-state-A.json> <monitor-state-B.json>');
      process.exit(2);
    }
    const a = JSON.parse(fs.readFileSync(aPath, 'utf8'));
    const b = JSON.parse(fs.readFileSync(bPath, 'utf8'));
    const res = compareJournals(a, b);
    console.log('-'.repeat(72));
    if (!res.equivocationDetected) {
      console.log('Compare: a ket journal konzisztens - nincs split-view.');
      process.exit(0);
    } else {
      for (const c of res.conflicts) console.log('  [EQUIVOCATION]', JSON.stringify(c));
      console.log('Compare: EQUIVOCATION BIZONYITVA - az operator eltero fakat mutatott a ket monitornak.');
      process.exit(1);
    }
  } else {
    console.error('Ismeretlen parancs. Hasznalat: poll | compare');
    process.exit(2);
  }
}
