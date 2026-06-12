// ═══════════════════════════════════════════════════════════════════════════════
// AXR - webhook kuldo + monitor OCSF/webhook integracio teszt
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-webhook-test.js
//
// Mit ellenoriz:
//   1. deliver: sikeres POST (payload, content-type, bearer token)
//   2. deliver: 5xx valasz -> ujraprobalkozas, delivered=false, NEM dob
//   3. deliver: elerheteetlen vegpont / rossz sema -> delivered=false, NEM dob
//   4. End-to-end (CLI): sertett log poll --webhook -> a szerver OCSF
//      Detection Findingokat kap, a kilepesi kod tovabbra is a detekcioe (1)
//   5. End-to-end: tiszta log -> nincs kuldes; webhook-hiba sem valtoztat
//      kilepesi kodot (best-effort export, a detekcio a hiteles)
//   6. --ocsf-out: a findingok JSONL-kent fajlba irodnak
//
// Nulla kulso fuggoseg.  Kilepesi kod: 0 zold, 1 hiba.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');
const axr = require('./axr-core');
const { runAnchor } = require('./axr-anchor');
const { deliver } = require('./axr-webhook');

let pass = 0, fail = 0;
function ok(cond, name) { if (cond) { pass++; } else { fail++; console.log('  FAIL: ' + name); } }
function section(t) { console.log('\n' + t); }

const T0 = () => '2026-06-12T10:00:00.000Z';

// Rogzito HTTP-szerver: minden kerest eltarol, konfiguralt statusszal valaszol.
function startServer() {
  const received = [];
  let respondWith = 200;
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      received.push({ headers: req.headers, body: Buffer.concat(chunks).toString('utf8') });
      res.statusCode = respondWith;
      res.end('{}');
    });
  });
  return new Promise(resolve => {
    server.listen(0, '127.0.0.1', () => resolve({
      url: 'http://127.0.0.1:' + server.address().port,
      received, setStatus: (s) => { respondWith = s; },
      close: () => new Promise(r => server.close(r))
    }));
  });
}

(async () => {
  const srv = await startServer();

  // ─────────────────────────────────────────────────────────────────────────
  section('1. deliver: sikeres POST');
  const payload = [{ class_uid: 2004, message: 'proba' }];
  const d1 = await deliver(srv.url + '/hook', payload, { token: 'titok123' });
  ok(d1.delivered && d1.status === 200 && d1.attempts === 1, 'kezbesitve elso kiserletre');
  const got = srv.received[srv.received.length - 1];
  ok(JSON.parse(got.body)[0].message === 'proba', 'a payload valtozatlanul erkezik');
  ok(got.headers['content-type'] === 'application/json', 'Content-Type: application/json');
  ok(got.headers['authorization'] === 'Bearer titok123', 'Bearer token a fejlecekben');

  // ─────────────────────────────────────────────────────────────────────────
  section('2. deliver: 5xx -> retry, delivered=false, nem dob');
  srv.setStatus(500);
  const before = srv.received.length;
  const d2 = await deliver(srv.url + '/hook', payload, { attempts: 2 });
  ok(!d2.delivered && d2.attempts === 2 && /HTTP 500/.test(d2.error), '2 kiserlet, delivered=false');
  ok(srv.received.length === before + 2, 'tenyleg ket POST ment ki');
  srv.setStatus(200);

  // ─────────────────────────────────────────────────────────────────────────
  section('3. deliver: elerheteetlen vegpont / rossz sema');
  const d3 = await deliver('http://127.0.0.1:1/hook', payload, { timeoutMs: 1500 });
  ok(!d3.delivered && d3.error, 'zart port -> delivered=false, nem dob');
  const d4 = await deliver('file:///etc/passwd', payload, {});
  ok(!d4.delivered && /sema/.test(d4.error), 'nem-http(s) sema elutasitva');

  // ─────────────────────────────────────────────────────────────────────────
  // End-to-end elokeszites: kis log a termelesi uton, majd sertes (tamper)
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-wh-'));
  const kp = crypto.generateKeyPairSync('ed25519');
  const priv = kp.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const pubPath = path.join(dir, 'pub.pem');
  fs.writeFileSync(pubPath, kp.publicKey.export({ type: 'spki', format: 'pem' }));
  const receiptsPath = path.join(dir, 'receipts.jsonl');
  const sthPath = path.join(dir, 'sth.jsonl');
  fs.writeFileSync(receiptsPath, [1, 2, 3].map(i => JSON.stringify({
    axr_version: '0.3', receipt_type: 'step', receipt_id: 'leaf-' + i,
    timestamp: T0(), io: { input_hash: axr.sha256('in-' + i) }
  })).join('\n') + '\n');
  await runAnchor({ receiptsPath, sthPath, anchorsPath: path.join(dir, 'anchors.jsonl'),
    backends: ['local'], logId: 'axr:wh-test:v1', privateKeyPem: priv, now: T0 });

  // ASZINKRON gyerekfolyamat: a tesztben futo HTTP-szerver csak akkor tud
  // valaszolni a CLI webhook-POST-jara, ha az event loop szabad marad
  // (execFileSync itt deadlockot okozna a timeoutig).
  function pollCli(extra, envExtra) {
    const args = [path.join(__dirname, 'axr-monitor.js'), 'poll', sthPath, pubPath,
      '--state', path.join(dir, 'mon-' + (pollCli.n = (pollCli.n || 0) + 1) + '.json'),
      '--receipts', receiptsPath, ...extra];
    return new Promise(resolve => {
      execFile('node', args, { encoding: 'utf8', env: { ...process.env, ...(envExtra || {}) } },
        (err, stdout, stderr) =>
          resolve({ code: err ? (err.code == null ? -1 : err.code) : 0, out: (stdout || '') + (stderr || '') }));
    });
  }

  // ─────────────────────────────────────────────────────────────────────────
  section('4. End-to-end: sertett log + --webhook -> OCSF findingok a szerveren');
  const sth = JSON.parse(fs.readFileSync(sthPath, 'utf8').trim());
  sth.root_hash = 'sha256:' + '0'.repeat(64); // tamper, nincs ujra-alairas
  fs.writeFileSync(sthPath, JSON.stringify(sth) + '\n');
  const beforeE2e = srv.received.length;
  const r4 = await pollCli(['--webhook', srv.url + '/axr']);
  ok(r4.code === 1, 'a kilepesi kod a detekcioe (1 - sertes)');
  ok(srv.received.length === beforeE2e + 1, 'pontosan egy webhook-POST ment ki');
  const findings = JSON.parse(srv.received[srv.received.length - 1].body);
  ok(Array.isArray(findings) && findings.length >= 1 &&
     findings.every(x => x.class_uid === 2004 && x.finding_info && x.finding_info.uid),
    'a payload OCSF Detection Finding tomb');
  ok(findings.some(x => x.unmapped.axr.code === 'BAD_SIGNATURE') &&
     findings.some(x => x.unmapped.axr.code === 'ROOT_MISMATCH'),
    'a tamper mindket varhato kodja (BAD_SIGNATURE, ROOT_MISMATCH) megjott');
  ok(findings.every(x => x.unmapped.axr.log_id === 'axr:wh-test:v1'), 'log_id a kontextusban');

  // ─────────────────────────────────────────────────────────────────────────
  section('5. End-to-end: webhook-hiba nem valtoztat kilepesi kodot');
  const r5 = await pollCli(['--webhook', 'http://127.0.0.1:1/axr']);
  ok(r5.code === 1 && /KEZBESITES SIKERTELEN/.test(r5.out),
    'elerheteetlen webhook: jelzes igen, de a kilepesi kod marad a detekcioe');

  // ─────────────────────────────────────────────────────────────────────────
  section('6. --ocsf-out fajlba + tiszta log nem kuld');
  const outPath = path.join(dir, 'findings.jsonl');
  const r6 = await pollCli(['--ocsf-out', outPath]);
  const lines = fs.readFileSync(outPath, 'utf8').trim().split('\n').map(JSON.parse);
  ok(r6.code === 1 && lines.length >= 2 && lines[0].class_uid === 2004,
    'a findingok JSONL-kent fajlba irodtak');
  // tiszta log: allitsuk vissza az eredeti STH-t ujraepitessel
  fs.rmSync(sthPath); fs.rmSync(path.join(dir, 'anchor-state.json'), { force: true });
  await runAnchor({ receiptsPath, sthPath, anchorsPath: path.join(dir, 'anchors.jsonl'),
    backends: ['local'], logId: 'axr:wh-test:v1', privateKeyPem: priv, now: T0 });
  const beforeClean = srv.received.length;
  const r7 = await pollCli(['--webhook', srv.url + '/axr']);
  ok(r7.code === 0 && /nincs finding/.test(r7.out) && srv.received.length === beforeClean,
    'tiszta log: exit 0, nincs kuldes');

  // ─────────────────────────────────────────────────────────────────────────
  section('7. Token fajlbol/env-bol + plaintext-figyelmeztetes (Meridian-review)');
  // ujra sertett allapot, hogy legyen mit kuldeni
  const sth7 = JSON.parse(fs.readFileSync(sthPath, 'utf8').trim());
  sth7.root_hash = 'sha256:' + '1'.repeat(64);
  fs.writeFileSync(sthPath, JSON.stringify(sth7) + '\n');
  const r8 = await pollCli(['--webhook', srv.url + '/axr'], { AXR_WEBHOOK_TOKEN: 'env-titok' });
  ok(srv.received[srv.received.length - 1].headers['authorization'] === 'Bearer env-titok',
    'token az AXR_WEBHOOK_TOKEN kornyezeti valtozobol');
  ok(/titkositatlan/.test(r8.out), 'http cel -> explicit plaintext-figyelmeztetes');
  const tokenFile = path.join(dir, 'token.txt');
  fs.writeFileSync(tokenFile, 'fajl-titok\n');
  await pollCli(['--webhook', srv.url + '/axr', '--webhook-token-file', tokenFile]);
  ok(srv.received[srv.received.length - 1].headers['authorization'] === 'Bearer fajl-titok',
    'token a --webhook-token-file fajlbol (trimmelt)');

  await srv.close();
  console.log(`\nOsszesen: ${pass} ok, ${fail} hiba`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('VARATLAN HIBA:', e); process.exit(1); });
