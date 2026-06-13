// ═══════════════════════════════════════════════════════════════════════════════
// AXR SDK - programozott teljes-log verifikacio (axr.verify)
// ═══════════════════════════════════════════════════════════════════════════════
// A teljes-log verifikacio a KANONIKUS verifikalo (axr-verify.js) - sok bemeneti
// fajl orchesztracioja, fagyasztott kilepesi kodokkal (0 ervenyes / 1 serult /
// 2 hasznalat-IO hiba; lasd AXR-SPEC-1.0.md). Ahhoz, hogy az SDK-verdikt SOSE
// terjen el a CLI-tol, ez a wrapper magat a kanonikus verifikalot futtatja egy
// gyermek-processzben es a FAGYASZTOTT kilepesi kodbol szarmaztatja az `ok`-ot.
//   - ok / exitCode: a fagyasztott szerzodesbol (megbizhato)
//   - problems / notices: a verifikalo jelolt sorai ([HIBA]/[megj]) best-effort
//     kigyujtve (ember-olvashato; a formatum NEM fagyott - a dontes a kilepesi kod)
//   - output: a verifikalo teljes (stdout+stderr) kimenete
//
// Aszinkron (I/O + opcionalis halozat a --online eseten). A spawn maga hibazik
// (pl. nincs node) -> reject; ha a verifikalo lefutott es kodot adott -> resolve.
// Nulla kulso fuggoseg.
// ═══════════════════════════════════════════════════════════════════════════════

const path = require('path');
const { spawn } = require('child_process');

const VERIFIER = path.join(__dirname, 'axr-verify.js');

// verifyLog(opts) -> Promise<{ ok, exitCode, problems, notices, output }>
//   opts (fajl-utak): { receipts, publicKey, sth?, anchors?, trustRoot?, control?,
//     successions?, revocations?, sthKey?, logId?, strict?, online?, requireWitnesses? }
function verifyLog(opts) {
  opts = opts || {};
  if (!opts.receipts || !opts.publicKey)
    return Promise.reject(new Error('axr.verify: a receipts es publicKey (fajl-utak) kotelezok'));

  const args = [VERIFIER, opts.receipts, opts.publicKey];
  if (opts.sth) args.push(opts.sth);
  if (opts.anchors) args.push(opts.anchors);
  if (opts.strict) args.push('--strict');
  if (opts.online) args.push('--online');
  if (opts.requireWitnesses) args.push('--require-witnesses');
  if (opts.sthKey) args.push('--sth-key', opts.sthKey);
  if (opts.trustRoot) args.push('--trust-root', opts.trustRoot);
  if (opts.successions) args.push('--successions', opts.successions);
  if (opts.revocations) args.push('--revocations', opts.revocations);
  if (opts.control) args.push('--control', opts.control);
  if (opts.logId) args.push('--log-id', opts.logId);

  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawn(process.execPath, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (e) { return reject(e); }
    let out = '', err = '';
    child.stdout.on('data', d => { out += d; });
    child.stderr.on('data', d => { err += d; });
    child.on('error', reject);
    child.on('close', (code) => {
      const lines = out.split('\n');
      const problems = lines.filter(l => l.indexOf('[HIBA]') !== -1)
        .map(l => l.replace(/^\s*\[HIBA\]\s?/, '').trim());
      const notices = lines.filter(l => l.indexOf('[megj]') !== -1)
        .map(l => l.replace(/^\s*\[megj\]\s?/, '').trim());
      // hasznalat/IO hiba (exit 2) eseten az uzenet a stderr-en jon
      if (code === 2 && err.trim()) problems.push(err.trim());
      resolve({ ok: code === 0, exitCode: code, problems, notices, output: out + (err || '') });
    });
  });
}

module.exports = { verifyLog };
