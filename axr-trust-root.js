#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════════════
// AXR - Trust root epito / ellenorzo (0.4)
// ═══════════════════════════════════════════════════════════════════════════════
// A trust-root egy root-kulccsal alairt, append nelkul nem bovitheto allowlist:
// provider-nevekhez rendeli a megengedett provider-publikuskulcsokat. Ez koti a
// side-effect attestation kulcsat egy konkret providerhez, lezarva az N1 lyukat
// ("az operator a sajatjat irja ala / sajat kulcsat nevezi google-calendar-nak").
//
// A root-kulcs az operatortol FUGGETLEN fel tulajdona (auditor / konzorcium /
// publikalt lista). A verifier --trust-root kapcsoloval kapja meg.
//
// Hasznalat:
//   # uj trust-root epitese egy egyszeru leiro JSON-bol
//   node axr-trust-root.js build providers.json root-priv.pem root-pub.pem > trust-root.json
//
//   # meglevo trust-root ellenorzese (integritas: a root-kulccsal verifikal-e)
//   node axr-trust-root.js verify trust-root.json
//
// A providers.json alakja:
//   [ { "provider": "google-calendar", "public_keys": ["-----BEGIN PUBLIC KEY----- ..."] },
//     { "provider": "stripe",          "public_keys": ["..."] } ]
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const core = require('./axr-core');

function die(msg, code) { console.error(msg); process.exit(code == null ? 2 : code); }

const [,, cmd, ...rest] = process.argv;

if (cmd === 'build') {
  const [providersPath, rootPrivPath, rootPubPath] = rest;
  if (!providersPath || !rootPrivPath || !rootPubPath) {
    die('Hasznalat: node axr-trust-root.js build <providers.json> <root-priv.pem> <root-pub.pem>');
  }
  let providers;
  try { providers = JSON.parse(fs.readFileSync(providersPath, 'utf8')); }
  catch (e) { die('HIBA: providers.json nem olvashato/ervenytelen: ' + e.message); }
  if (!Array.isArray(providers)) die('HIBA: a providers.json gyokere tomb kell legyen');
  const rootPriv = fs.readFileSync(rootPrivPath, 'utf8');
  const rootPub = fs.readFileSync(rootPubPath, 'utf8');
  const tr = core.buildTrustRoot(providers, rootPriv, rootPub);
  // onellenorzes mielott kiirjuk
  const chk = core.verifyTrustRoot(tr);
  if (!chk.ok) die('HIBA: a felepitett trust-root nem verifikal: ' + chk.problems.join('; '), 1);
  process.stdout.write(JSON.stringify(tr) + '\n');
  process.exit(0);
}

if (cmd === 'verify') {
  const [trPath] = rest;
  if (!trPath) die('Hasznalat: node axr-trust-root.js verify <trust-root.json>');
  let tr;
  try { tr = JSON.parse(fs.readFileSync(trPath, 'utf8')); }
  catch (e) { die('HIBA: trust-root nem olvashato/ervenytelen: ' + e.message); }
  const res = core.verifyTrustRoot(tr);
  if (res.ok) {
    const n = (tr.providers || []).length;
    const keys = (tr.providers || []).reduce((a, p) => a + (p.public_keys || []).length, 0);
    console.log(`Trust-root ERVENYES. ${n} provider, ${keys} kulcs. issued_at: ${tr.issued_at}`);
    process.exit(0);
  } else {
    console.log('Trust-root ERVENYTELEN: ' + res.problems.join('; '));
    process.exit(1);
  }
}

die('Hasznalat: node axr-trust-root.js <build|verify> ...');
