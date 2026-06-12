// ═══════════════════════════════════════════════════════════════════════════════
// AXR 0.5 - monitor + key succession (teszt)
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-monitor-succession-test.js
//
// Mit ellenoriz:
//   1. Backward-kompat: trust-root NELKUL a rotalt log ma is sertes (TOFU)
//   2. Trust-roottal az autorizalt rotacio atmegy: KEY_ROTATED_AUTHORIZED
//      megjegyzes, nincs sertes, a journal bovul (aktiv kulcs + lanc-hash)
//   3. A pinned kulcs csereje: autorizalt utodra -> megjegyzes; idegenre -> sertes
//   4. Red-team: hamis root-tal alairt succession -> KEY_CHANGED_UNAUTHORIZED
//   5. Red-team: be-nem-jelentett kulcscsere -> BAD_SIGNATURE (idovonal-kulcsra)
//   6. Degradalt mod: trust-root e log genesise nelkul -> TOFU marad, jelzessel
//   7. compareJournals: divergens succession-lanc = konfliktus; hianyzo mezo nem
//   8. Sefult trust-root -> TRUST_ROOT_INVALID (fail-closed)
//
// A logokat a TERMELESI uton epitjuk (runAnchor), nem kezzel - igy a sidecar es
// a monitor egyutt is bizonyitott.  Kilepesi kod: 0 zold, 1 hiba.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const axr = require('./axr-core');
const s = require('./axr-succession');
const { runAnchor } = require('./axr-anchor');
const { pollMonitor, compareJournals } = require('./axr-monitor');

let pass = 0, fail = 0;
function ok(cond, name) { if (cond) { pass++; } else { fail++; console.log('  FAIL: ' + name); } }
function section(t) { console.log('\n' + t); }
function codes(res) { return res.violations.map(v => v.code); }
function noticeText(res) { return res.notices.join(' | '); }

function genKey() {
  const kp = crypto.generateKeyPairSync('ed25519');
  return {
    privateKey: kp.privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicKey: kp.publicKey.export({ type: 'spki', format: 'pem' })
  };
}

const T0 = () => '2026-06-12T00:00:00.000Z';
const LOG = 'axr:monitor-succ-test:v1';

// root (bizalmi horgony), A (genesis sth), B (utod), X (idegen), fakeRoot (tamado)
const root = genKey(), A = genKey(), B = genKey(), X = genKey(), fakeRoot = genKey();
const fpB = s.keyFingerprint(B.publicKey);

const trustRoot = s.buildTrustRoot({
  providers: [],
  logs: [{ log_id: LOG, genesis: { sth: A.publicKey, receipt: null } }]
}, root.privateKey, root.publicKey, T0);

let leafSeq = 0;
function appendLeaves(p, n) {
  const out = [];
  for (let i = 0; i < n; i++) {
    leafSeq++;
    out.push({ axr_version: '0.3', receipt_type: 'step', receipt_id: 'leaf-' + leafSeq,
      timestamp: T0(), io: { input_hash: axr.sha256('in-' + leafSeq) } });
  }
  fs.appendFileSync(p, out.map(r => JSON.stringify(r)).join('\n') + '\n');
}

// Egy log felepitese a termelesi uton: A alair 3 levelet, majd (opcionalisan)
// rotacio utan a masodik kulcs tovabbi 2+1 levelet.
async function buildLog(dir, secondKey, succession) {
  const receiptsPath = path.join(dir, 'receipts.jsonl');
  const base = { receiptsPath, sthPath: path.join(dir, 'sth.jsonl'),
    anchorsPath: path.join(dir, 'anchors.jsonl'), backends: ['local'], logId: LOG, now: T0 };
  fs.writeFileSync(receiptsPath, '');
  appendLeaves(receiptsPath, 3);
  await runAnchor({ ...base, privateKeyPem: A.privateKey });
  if (secondKey) {
    appendLeaves(receiptsPath, 2);
    await runAnchor({ ...base, privateKeyPem: secondKey.privateKey, succession });
    appendLeaves(receiptsPath, 1);
    await runAnchor({ ...base, privateKeyPem: secondKey.privateKey, succession });
  }
  return base;
}

(async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-monsucc-'));
  const mkdir = (n) => { const d = path.join(tmp, n); fs.mkdirSync(d); return d; };

  // Szabalyos, rotalt log: A (1..3), succession A->B eff=4, B (4..6)
  const succAB = s.buildKeySuccession({
    log_id: LOG, role: 'sth', predecessor_fingerprint: s.keyFingerprint(A.publicKey),
    successor_public_key: B.publicKey, effective_from_tree_size: 4, reason: 'scheduled'
  }, root.privateKey, T0);
  const dirGood = mkdir('good');
  const good = await buildLog(dirGood, B, succAB);

  // ─────────────────────────────────────────────────────────────────────────
  section('1. Backward-kompat: trust-root nelkul a rotalt log sertes (TOFU)');
  const res1 = pollMonitor({ sthPath: good.sthPath, publicKeyPem: A.publicKey,
    statePath: path.join(dirGood, 'mon-tofu.json'), receiptsPath: good.receiptsPath, now: T0 });
  ok(!res1.ok, 'trust-root nelkul: a rotacio sertest ad (a mai viselkedes)');
  ok(codes(res1).includes('BAD_SIGNATURE'), 'a B-vel alairt STH a pinned A-ra BAD_SIGNATURE');

  // ─────────────────────────────────────────────────────────────────────────
  section('2. Trust-roottal az autorizalt rotacio atmegy');
  const stGood = path.join(dirGood, 'mon-tr.json');
  const res2 = pollMonitor({ sthPath: good.sthPath, publicKeyPem: A.publicKey,
    statePath: stGood, receiptsPath: good.receiptsPath, trustRoot, now: T0 });
  ok(res2.ok, 'nincs sertes (autorizalt rotacio): ' + JSON.stringify(res2.violations));
  ok(/KEY_ROTATED_AUTHORIZED/.test(noticeText(res2)), 'KEY_ROTATED_AUTHORIZED megjegyzes');
  const st2 = JSON.parse(fs.readFileSync(stGood, 'utf8'));
  ok(st2.active_key_fingerprint === fpB, 'journal: aktiv kulcs = B fingerprintje');
  ok(typeof st2.succession_chain_hash === 'string' && st2.succession_chain_hash.startsWith('sha256:'),
    'journal: succession-lanc-hash rogzitve');
  const res2b = pollMonitor({ sthPath: good.sthPath, publicKeyPem: A.publicKey,
    statePath: stGood, receiptsPath: good.receiptsPath, trustRoot, now: T0 });
  ok(res2b.ok, 'idempotens ujrapoll: tovabbra is ok');

  // ─────────────────────────────────────────────────────────────────────────
  section('3. A pinned kulcs csereje: autorizalt utod vs idegen kulcs');
  const res3 = pollMonitor({ sthPath: good.sthPath, publicKeyPem: B.publicKey,
    statePath: stGood, receiptsPath: good.receiptsPath, trustRoot, now: T0 });
  ok(res3.ok, 'pinned kulcs -> B (autorizalt utod): nincs sertes');
  ok(/KEY_ROTATED_AUTHORIZED.*pinned/.test(noticeText(res3)), 'a pinned-csere megjegyzeskent jelenik meg');
  ok(JSON.parse(fs.readFileSync(stGood, 'utf8')).public_key_fingerprint === fpB,
    'a journal pinned fingerprintje B-re frissult');
  const res3b = pollMonitor({ sthPath: good.sthPath, publicKeyPem: X.publicKey,
    statePath: stGood, receiptsPath: good.receiptsPath, trustRoot, now: T0 });
  ok(codes(res3b).includes('KEY_CHANGED_UNAUTHORIZED'), 'pinned kulcs -> X (idegen): KEY_CHANGED_UNAUTHORIZED');

  // ─────────────────────────────────────────────────────────────────────────
  section('4. Red-team: hamis root-tal alairt succession');
  const forged = s.buildKeySuccession({
    log_id: LOG, role: 'sth', predecessor_fingerprint: s.keyFingerprint(A.publicKey),
    successor_public_key: X.publicKey, effective_from_tree_size: 4, reason: 'compromise'
  }, fakeRoot.privateKey, T0);
  const dirForged = mkdir('forged');
  const forgedLog = await buildLog(dirForged, X, forged);
  const res4 = pollMonitor({ sthPath: forgedLog.sthPath, publicKeyPem: A.publicKey,
    statePath: path.join(dirForged, 'mon.json'), receiptsPath: forgedLog.receiptsPath, trustRoot, now: T0 });
  ok(!res4.ok, 'hamis succession: sertes');
  ok(codes(res4).includes('KEY_CHANGED_UNAUTHORIZED'),
    'a beagyazott succession root-verifikacioja bukik -> KEY_CHANGED_UNAUTHORIZED');
  ok(codes(res4).includes('BAD_SIGNATURE'), 'az X-szel alairt STH az idovonal (A) kulcsara is bukik');

  // ─────────────────────────────────────────────────────────────────────────
  section('5. Red-team: be-nem-jelentett kulcscsere (nincs succession)');
  const dirSilent = mkdir('silent');
  const silentLog = await buildLog(dirSilent, X, undefined);
  const res5 = pollMonitor({ sthPath: silentLog.sthPath, publicKeyPem: A.publicKey,
    statePath: path.join(dirSilent, 'mon.json'), receiptsPath: silentLog.receiptsPath, trustRoot, now: T0 });
  ok(!res5.ok, 'csendes kulcscsere: sertes');
  ok(codes(res5).includes('BAD_SIGNATURE'), 'BAD_SIGNATURE az idovonal szerinti kulcsra');

  // ─────────────────────────────────────────────────────────────────────────
  section('6. Degradalt mod: a trust-root nem ismeri ezt a logot');
  const trEmpty = s.buildTrustRoot({ providers: [], logs: [] }, root.privateKey, root.publicKey, T0);
  const res6 = pollMonitor({ sthPath: good.sthPath, publicKeyPem: A.publicKey,
    statePath: path.join(dirGood, 'mon-degr.json'), receiptsPath: good.receiptsPath,
    trustRoot: trEmpty, now: T0 });
  ok(/DEGRADED/.test(noticeText(res6)), 'explicit DEGRADED jelzes');
  ok(!res6.ok && codes(res6).includes('BAD_SIGNATURE'), 'degradalt mod = TOFU: a rotacio sertes marad');

  // ─────────────────────────────────────────────────────────────────────────
  section('7. compareJournals: divergens succession-lanc = konfliktus');
  const base7 = { log_id: LOG, public_key_fingerprint: 'fp',
    witnessed: [{ tree_size: 3, root_hash: axr.sha256('ua') }] };
  const cmp1 = compareJournals(
    { ...base7, succession_chain_hash: axr.sha256('lanc-1') },
    { ...base7, succession_chain_hash: axr.sha256('lanc-2') });
  ok(cmp1.equivocationDetected && cmp1.conflicts.some(c => c.succession_chain_mismatch),
    'ket kulonbozo lanc-hash -> konfliktus (split-view a kulcs-tortenetben)');
  const cmp2 = compareJournals({ ...base7 }, { ...base7 });
  ok(!cmp2.equivocationDetected, 'hianyzo lanc-mezok (0.3-as journalok) -> nincs konfliktus');
  const cmp3 = compareJournals({ ...base7, succession_chain_hash: axr.sha256('lanc-1') }, { ...base7 });
  ok(!cmp3.equivocationDetected, 'egyik oldali hianyzo mezo (idozites) -> nincs teves riasztas');

  // ─────────────────────────────────────────────────────────────────────────
  section('8. Serult trust-root -> fail-closed');
  const badTr = JSON.parse(JSON.stringify(trustRoot));
  badTr.logs[0].genesis.sth = X.publicKey; // utolagos atiras, nincs ujra-alairas
  const res8 = pollMonitor({ sthPath: good.sthPath, publicKeyPem: A.publicKey,
    statePath: path.join(dirGood, 'mon-badtr.json'), receiptsPath: good.receiptsPath,
    trustRoot: badTr, now: T0 });
  ok(!res8.ok && codes(res8).includes('TRUST_ROOT_INVALID'),
    'manipulalt trust-root -> TRUST_ROOT_INVALID, semmilyen kulcs-allitas nem ervenyesul');

  // ─────────────────────────────────────────────────────────────────────────
  section('9. Lanc-hash determinizmus: forked (azonos effective_from) successionok');
  // Ket root-alairt, KONKURALO succession ugyanarra a hatarra (fork). Ket monitor
  // eltero sorrendben kapja oket - a lanc-hashuknek AZONOSNAK kell lennie,
  // kulonben ket becsuletes monitor compare-je vakriasztast adna.
  const C1 = genKey(), C2 = genKey();
  const succBC1 = s.buildKeySuccession({
    log_id: LOG, role: 'sth', predecessor_fingerprint: fpB,
    successor_public_key: C1.publicKey, effective_from_tree_size: 10, reason: 'fork-1'
  }, root.privateKey, T0);
  const succBC2 = s.buildKeySuccession({
    log_id: LOG, role: 'sth', predecessor_fingerprint: fpB,
    successor_public_key: C2.publicKey, effective_from_tree_size: 10, reason: 'fork-2'
  }, root.privateKey, T0);
  const stM1 = path.join(dirGood, 'mon-ord1.json'), stM2 = path.join(dirGood, 'mon-ord2.json');
  const res9a = pollMonitor({ sthPath: good.sthPath, publicKeyPem: A.publicKey, statePath: stM1,
    receiptsPath: good.receiptsPath, trustRoot, successions: [succBC1, succBC2], now: T0 });
  const res9b = pollMonitor({ sthPath: good.sthPath, publicKeyPem: A.publicKey, statePath: stM2,
    receiptsPath: good.receiptsPath, trustRoot, successions: [succBC2, succBC1], now: T0 });
  ok(res9a.ok && res9b.ok, 'a jovobeli fork meg nem sertes (nincs vele alairt STH)');
  const j1 = JSON.parse(fs.readFileSync(stM1, 'utf8')), j2 = JSON.parse(fs.readFileSync(stM2, 'utf8'));
  ok(j1.succession_chain_hash === j2.succession_chain_hash,
    'eltero beerkezesi sorrend -> azonos lanc-hash (determinisztikus rendezes)');
  ok(!compareJournals(j1, j2).equivocationDetected,
    'a ket becsuletes monitor compare-je nem ad vakriasztast');
  ok(/utkozes|sorrend/.test(noticeText(res9a)), 'a fork utkozeskent jelezve (a forked kulcs nem autorizalt)');

  // ─────────────────────────────────────────────────────────────────────────
  console.log(`\nOsszesen: ${pass} ok, ${fail} hiba`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('VARATLAN HIBA:', e); process.exit(1); });
