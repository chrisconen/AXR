// ═══════════════════════════════════════════════════════════════════════════════
// AXR - generikus webhook kuldo (0.5+)
// ═══════════════════════════════════════════════════════════════════════════════
// Egyetlen feladata: egy JSON-payload (tipikusan OCSF Detection Finding tomb,
// lasd axr-ocsf.js) kezbesitese egy operator-konfiguralt HTTP(S) vegpontra.
// Generikus: nincs vendor-specifikus formazas - a cel vegpont (SIEM collector,
// Slack/Teams proxy, sajat backend) dolga a tovabbi alakitas.
//
// Tervezesi elvek:
//   - A kezbesites BEST-EFFORT: a detektalas eredmenye (exit code, journal) a
//     hiteles; a webhook-hiba jelzest ad, de nem valtoztat a detekcion. Egy
//     elerheteetlen SIEM nem nemithatja el a monitort - es nem is "buktathatja
//     el" a konzisztens logot.
//   - Ujraprobalkozas: alapbol 2 kiserlet (1 retry), exponencialis varakozas
//     nelkul - a monitor poll-onkent ugyis ujra fut, a tartos sorba-allitas a
//     fogado oldal dolga.
//   - Csak http/https sema engedett; minden mas (file:, stb.) hiba.
//
// Trust-hatar (kimondva, Meridian-review nyoman): a webhook URL es a token
// OPERATOR-konfig - a modell szerint megbizhato bemenet. Ha az URL valaha
// delegalt/untrusted forrasbol johetne, a hivo oldalon kell URL-allowlist
// (SSRF/egress kontroll) - ezt a kuldo szandekosan nem talalja ki helyette.
// http: cel eseten az export titkositatlan - a monitor CLI explicit jelzi.
// A tokent fajlbol vagy kornyezeti valtozobol erdemes adni, nem CLI-argkent
// (process-lista / shell-history kitettseg) - lasd a monitor kapcsoloit.
//
// Nulla kulso fuggoseg - csak a Node beepitett http/https.
// ═══════════════════════════════════════════════════════════════════════════════

const http = require('http');
const https = require('https');

// Egyetlen POST. -> Promise<{ status, body }> vagy throw.
function postOnce(url, bodyStr, opts) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(url); } catch (e) { return reject(new Error('ervenytelen URL: ' + e.message)); }
    if (u.protocol !== 'https:' && u.protocol !== 'http:')
      return reject(new Error('csak http/https sema engedett, kapott: ' + u.protocol));
    const mod = u.protocol === 'https:' ? https : http;
    const headers = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(bodyStr, 'utf8'),
      'User-Agent': 'axr-webhook/0.5'
    };
    if (opts && opts.token) headers['Authorization'] = 'Bearer ' + opts.token;
    const req = mod.request({
      hostname: u.hostname, port: u.port || undefined,
      path: u.pathname + u.search, method: 'POST',
      headers, timeout: (opts && opts.timeoutMs) || 8000
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf8');
        if (res.statusCode >= 200 && res.statusCode < 300) resolve({ status: res.statusCode, body });
        else reject(new Error('HTTP ' + res.statusCode));
      });
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.write(bodyStr);
    req.end();
  });
}

// Fo belepo: payload kezbesitese ujraprobalkozassal.
//   opts: { token, timeoutMs, attempts (default 2) }
// -> { delivered: bool, status?: number, attempts: number, error?: string }
// SOSEM dob: a hivonak (monitor CLI) jelzes kell, nem kivetel.
async function deliver(url, payload, opts) {
  const o = opts || {};
  const attempts = o.attempts || 2;
  const bodyStr = JSON.stringify(payload);
  let lastErr = null;
  for (let i = 1; i <= attempts; i++) {
    try {
      const r = await postOnce(url, bodyStr, o);
      return { delivered: true, status: r.status, attempts: i };
    } catch (e) { lastErr = e; }
  }
  return { delivered: false, attempts, error: lastErr ? lastErr.message : 'ismeretlen hiba' };
}

module.exports = { deliver, postOnce };
