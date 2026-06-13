// ═══════════════════════════════════════════════════════════════════════════════
// AXR - production rollout tooling teszt (bootstrap + preflight)
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-rollout-test.js
//
// Mit ellenoriz:
//   1. bootstrap (CLI): single + kvorum trust-root a meglevo kulcsokbol, a
//      kimenet verifikal, a genesis a megadott kulcs
//   2. preflight GO: helyesen bootstrapelt deployment (genesis == tenyleges
//      alairo, opentimestamps anchor) -> go=true, GENESIS_SIGNS ok
//   3. preflight NO-GO self-lockout: a genesis NEM a tenyleges STH-alairo ->
//      GENESIS_MISMATCH blocker
//   4. preflight blockerek: ervenytelen trust-root; commitolo STH control nelkul
//   5. preflight figyelmeztetesek: csak local anchor (N3), nincs monitor (N4),
//      kvorum threshold=1
//
// Nulla kulso fuggoseg.  Kilepesi kod: 0 zold, 1 hiba.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const axr = require('./axr-core');
const s = require('./axr-succession');
const { runAnchor } = require('./axr-anchor');
const { preflight } = require('./axr-rollout');

let pass = 0, fail = 0;
function ok(cond, name) { if (cond) { pass++; } else { fail++; console.log('  FAIL: ' + name); } }
function section(t) { console.log('\n' + t); }
function codes(res) { return res.findings.map(f => f.code); }
function levelOf(res, code) { const f = res.findings.find(x => x.code === code); return f ? f.level : null; }

function genKey() {
  const kp = crypto.generateKeyPairSync('ed25519');
  return { privateKey: kp.privateKey.export({ type: 'pkcs8', format: 'pem' }),
           publicKey: kp.publicKey.export({ type: 'spki', format: 'pem' }) };
}
const T0 = () => '2026-06-13T09:00:00.000Z';
const LOG = 'axr:rollout-test:v1';
const opKey = genKey();   // a futo pilot operator-kulcsa (STH + receipt egyben)
const rootK = genKey();   // uj root a bootstraphoz
const otherKey = genKey();

const CLI = path.join(__dirname, 'axr-rollout.js');
function runCli(args) {
  try { return { code: 0, out: execFileSync('node', [CLI, ...args], { encoding: 'utf8', stdio: 'pipe' }) }; }
  catch (e) { return { code: e.status == null ? -1 : e.status, out: (e.stdout || '') + (e.stderr || '') }; }
}

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-rollout-'));
  const W = (n, c) => { const p = path.join(dir, n); fs.writeFileSync(p, c); return p; };
  const opPubPath = W('op-pub.pem', opKey.publicKey);
  const rootPrivPath = W('root-priv.pem', rootK.privateKey);

  // egy futo pilot-log: az operator-kulcs irja az STH-kat (TOFU-szeruen)
  const receiptsPath = path.join(dir, 'receipts.jsonl');
  const sthPath = path.join(dir, 'sth.jsonl');
  const anchorsPath = path.join(dir, 'anchors.jsonl');
  fs.writeFileSync(receiptsPath, '');
  function appendLeaves(n) {
    const out = [];
    for (let i = 0; i < n; i++) out.push({ axr_version: '0.3', receipt_type: 'step',
      receipt_id: 'leaf-' + Math.random().toString(36).slice(2), timestamp: T0(),
      io: { input_hash: axr.sha256('x' + Math.random()) } });
    fs.appendFileSync(receiptsPath, out.map(r => JSON.stringify(r)).join('\n') + '\n');
  }
  const base = { receiptsPath, sthPath, anchorsPath, backends: ['opentimestamps'], logId: LOG, now: T0 };
  appendLeaves(3);
  await runAnchor({ ...base, privateKeyPem: opKey.privateKey, timeoutMs: 1 }); // OTS halozat nelkul: pending_offline, de anchor-rekord keletkezik

  // ─────────────────────────────────────────────────────────────────────────
  section('1. bootstrap (CLI)');
  const bsSingle = runCli(['bootstrap', '--log-id', LOG, '--sth-pub', opPubPath, '--receipt-pub', opPubPath,
    '--root-priv', rootPrivPath]);
  ok(bsSingle.code === 0, 'single bootstrap: exit 0');
  const trSingle = JSON.parse(bsSingle.out);
  ok(s.verifyTrustRoot(trSingle).ok, 'a bootstrapelt single trust-root verifikal');
  ok(s.genesisKey(trSingle, LOG, 'sth') === opKey.publicKey, 'a genesis sth a megadott operator-kulcs');
  // kvorum bootstrap (a privatokbol szarmaztatott publikus keszlet)
  const q1 = genKey(), q2 = genKey(), q3 = genKey();
  const q1p = W('q1.pem', q1.privateKey), q2p = W('q2.pem', q2.privateKey), q3p = W('q3.pem', q3.privateKey);
  const bsQ = runCli(['bootstrap', '--log-id', LOG, '--sth-pub', opPubPath,
    '--root-privs', [q1p, q2p, q3p].join(','), '--threshold', '2']);
  ok(bsQ.code === 0 && s.verifyTrustRoot(JSON.parse(bsQ.out)).ok, 'kvorum bootstrap (2-of-3): verifikal');
  ok(s.trustRootMode(JSON.parse(bsQ.out)).mode === 'quorum', 'a kvorum trust-root mode=quorum');

  const trPath = W('trust-root.json', JSON.stringify(trSingle) + '\n');

  // ─────────────────────────────────────────────────────────────────────────
  section('2. preflight GO (helyes bootstrap)');
  const okVerifier = () => ({ code: 0, ok: true });
  const inputsBase = {
    receipts: fs.readFileSync(receiptsPath, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse),
    sths: fs.readFileSync(sthPath, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse).filter(r => r.record_type === 'sth'),
    anchors: fs.readFileSync(anchorsPath, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse).filter(r => r.record_type === 'anchor'),
    trustRoot: [trSingle], logId: LOG, monitorState: {}, runVerifier: okVerifier
  };
  const resGo = preflight({ ...inputsBase });
  ok(resGo.go === true, 'go=true (helyes deployment): ' + JSON.stringify(resGo.findings.filter(f => f.level === 'blocker')));
  ok(levelOf(resGo, 'GENESIS_SIGNS') === 'ok', 'GENESIS_SIGNS: a genesis alairja a legkorabbi STH-t');
  ok(levelOf(resGo, 'ANCHOR_OK') === 'ok', 'ANCHOR_OK: opentimestamps fuggetlen backend');
  ok(levelOf(resGo, 'TRUST_ROOT_OK') === 'ok', 'TRUST_ROOT_OK');

  // ─────────────────────────────────────────────────────────────────────────
  section('3. preflight NO-GO: self-lockout (genesis != tenyleges alairo)');
  // a trust-root genesis-e egy IDEGEN kulcs, nem a tenyleges STH-alairo
  const trWrong = s.buildTrustRoot({ providers: [], logs: [{ log_id: LOG,
    genesis: { sth: otherKey.publicKey, receipt: otherKey.publicKey } }] }, rootK.privateKey, rootK.publicKey, T0);
  const resLock = preflight({ ...inputsBase, trustRoot: [trWrong] });
  ok(resLock.go === false, 'go=false (self-lockout)');
  ok(levelOf(resLock, 'GENESIS_MISMATCH') === 'blocker',
    'GENESIS_MISMATCH blocker: a deklaralt genesis nem irja ala a legkorabbi STH-t');

  // ─────────────────────────────────────────────────────────────────────────
  section('4. preflight blockerek');
  // 4a. ervenytelen trust-root (utolagos atiras)
  const trTampered = JSON.parse(JSON.stringify(trSingle));
  trTampered.logs[0].genesis.sth = otherKey.publicKey;
  const resBadTr = preflight({ ...inputsBase, trustRoot: [trTampered] });
  ok(resBadTr.go === false && codes(resBadTr).includes('TRUST_ROOT_INVALID'),
    'manipulalt trust-root -> TRUST_ROOT_INVALID blocker');
  // 4b. commitolo STH control nelkul
  const committedSth = { ...inputsBase.sths[0], control_root_hash: 'sha256:' + 'a'.repeat(64), control_size: 1 };
  const resNoCtl = preflight({ ...inputsBase, sths: [committedSth], control: null });
  ok(codes(resNoCtl).includes('CONTROL_WITHHELD') && levelOf(resNoCtl, 'CONTROL_WITHHELD') === 'blocker',
    'commitolo STH control log nelkul -> CONTROL_WITHHELD blocker');

  // ─────────────────────────────────────────────────────────────────────────
  section('5. preflight figyelmeztetesek (nem blockerek)');
  // local-only anchor + nincs monitor
  const resWarn = preflight({ ...inputsBase,
    anchors: [{ record_type: 'anchor', backend: 'local', tree_size: 3 }], monitorState: null });
  ok(levelOf(resWarn, 'LOCAL_ANCHOR_ONLY') === 'warning', 'csak local anchor -> warning (N3)');
  ok(levelOf(resWarn, 'NO_MONITOR') === 'warning', 'nincs monitor -> warning (N4)');
  ok(resWarn.go === true, 'figyelmeztetesek onmagukban NEM blokkolnak (go marad)');
  // kvorum threshold=1
  const trQ1 = s.buildQuorumTrustRoot({ providers: [], logs: [{ log_id: LOG,
    genesis: { sth: opKey.publicKey, receipt: opKey.publicKey } }],
    root_keys: [q1.publicKey, q2.publicKey], threshold: 1 }, [q1.privateKey], T0);
  const resQ1 = preflight({ ...inputsBase, trustRoot: [trQ1] });
  ok(levelOf(resQ1, 'QUORUM_THRESHOLD_1') === 'warning', 'kvorum threshold=1 -> warning');

  // ─────────────────────────────────────────────────────────────────────────
  section('6. Meridian-review: kotelezo verifier + rotacio + monitor-genesis');
  // 6a. verifier nelkul NINCS GO (NO_VERIFIER blocker)
  const resNoVer = preflight({ ...inputsBase, runVerifier: null });
  ok(resNoVer.go === false && codes(resNoVer).includes('NO_VERIFIER'),
    'runVerifier nelkul -> NO_VERIFIER blocker, nincs GO');
  // 6b. buko verifier -> VERIFIER_FAIL blocker
  const resVerFail = preflight({ ...inputsBase, runVerifier: () => ({ code: 1, ok: false }) });
  ok(resVerFail.go === false && codes(resVerFail).includes('VERIFIER_FAIL'),
    'buko verifier -> VERIFIER_FAIL blocker');
  // 6c. rotalt log: a genesis alairja a legkorabbit, de egy kesobbi STH-t mas kulcs
  //     -> ROTATION_PRESENT warning, NEM hamis GENESIS_SIGNS
  const sthsRotated = inputsBase.sths.concat([
    JSON.parse(JSON.stringify({ ...inputsBase.sths[0], tree_size: 99,
      // mas kulccsal "alairt" STH: az opKey helyett otherKey-jel ujraalairva
    }))]);
  // valodi mas-kulcs alairas: epitsunk egy STH-t otherKey-jel
  const rotatedSth = (() => {
    const body = { axr_version: '0.3', record_type: 'sth', log_id: LOG, tree_size: 99,
      root_hash: 'sha256:' + 'b'.repeat(64), timestamp: T0(), previous_sth_hash: null };
    body.signature = axr.signReceipt(body, otherKey.privateKey);
    return body;
  })();
  const resRot = preflight({ ...inputsBase, sths: [inputsBase.sths[0], rotatedSth] });
  ok(levelOf(resRot, 'ROTATION_PRESENT') === 'warning' && levelOf(resRot, 'GENESIS_SIGNS') !== 'ok',
    'rotalt log: ROTATION_PRESENT warning, NINCS hamis GENESIS_SIGNS ok');
  // 6d. monitor pinned genesis != megadott trust-root -> MONITOR_GENESIS_MISMATCH blocker
  const pinnedOther = axr.sha256(trWrong); // egy MASIK trust-root genesis hashe
  const resMonMM = preflight({ ...inputsBase, monitorState: { trust_root_genesis_hash: pinnedOther } });
  ok(resMonMM.go === false && codes(resMonMM).includes('MONITOR_GENESIS_MISMATCH'),
    'eltero pinned genesis a monitor-journalban -> MONITOR_GENESIS_MISMATCH blocker');
  // 6e. egyezo pinned genesis -> MONITOR_GENESIS_OK
  const pinnedSame = axr.sha256(trSingle);
  const resMonOk = preflight({ ...inputsBase, monitorState: { trust_root_genesis_hash: pinnedSame } });
  ok(levelOf(resMonOk, 'MONITOR_GENESIS_OK') === 'ok', 'egyezo pinned genesis -> MONITOR_GENESIS_OK');

  console.log(`\nOsszesen: ${pass} ok, ${fail} hiba`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('VARATLAN HIBA:', e); process.exit(1); });
