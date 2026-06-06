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
//        [--backend local|opentimestamps] [--log-id axr:agent:v1]
//
// Nulla kulso fuggoseg - csak a Node beepitett moduljai + a kozos axr-core.js.
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');
const https = require('https');
const axr = require('./axr-core');

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

  // 1. Uj STH a teljes jelenlegi fa felett, az elozohoz lancolva
  const rootHash = axr.merkleRootFromLeaves(leafHashes);
  const sthBody = {
    axr_version: '0.3', record_type: 'sth', log_id: logId,
    tree_size: leaves.length, root_hash: rootHash, timestamp: now(),
    previous_sth_hash: lastSth ? axr.chainHash(lastSth) : null
  };
  sthBody.signature = axr.signReceipt(sthBody, opts.privateKeyPem);
  appendJsonl(sthPath, [sthBody]);

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

module.exports = { runAnchor, OTS_CALENDARS, LEAF_TYPES };

// ── CLI ──────────────────────────────────────────────────────────────────────
if (require.main === module) {
  const args = process.argv.slice(2);
  const positional = [];
  const flags = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith('--')) { flags[args[i].slice(2)] = args[i + 1]; i++; }
    else positional.push(args[i]);
  }
  const [receiptsPath, keyPath] = positional;
  if (!receiptsPath || !keyPath) {
    console.error('Hasznalat: node axr-anchor.js <receipts.jsonl> <private-key.pem> ' +
      '[--sth sth.jsonl] [--anchors anchors.jsonl] [--backend local|opentimestamps] [--log-id axr:agent:v1]');
    process.exit(2);
  }
  const privateKeyPem = fs.readFileSync(keyPath, 'utf8');
  runAnchor({
    receiptsPath, privateKeyPem,
    sthPath: flags.sth, anchorsPath: flags.anchors,
    backends: flags.backend ? [flags.backend] : ['local'],
    logId: flags['log-id']
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
