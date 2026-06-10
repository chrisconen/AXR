#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════════════
// AXR Workflow Lint - logic_version / kod-drift ellenorzo
// ═══════════════════════════════════════════════════════════════════════════════
// PROBLEMA: a Receipt Generator STEP_NODES tablaja kezzel karbantartott
// logic_version erteket ir a receiptekbe. Ha egy node kodja valtozik (bugfix),
// de a generator konstansa nem, akkor minden uj receipt HAMISAN tanusitja,
// melyik logika hozta a dontest. Ez nem tamper, hanem minoseghiba - de egy
// auditor szemeben pont az a drift, amit a rendszernek el kene kapnia.
//
// MIT CSINAL:
//   1. Beolvassa az n8n workflow JSON-t.
//   2. Minden Code node-bol kiolvassa a fejlec-verziot (vN.N minta az elso
//      kommentblokkban) es kiszamolja a jsCode SHA-256 ujjlenyomatat.
//   3. Megkeresi az "AXR Receipt Generator" node-ot, kiparszolja a STEP_NODES
//      logic_version (es ha van, logic_hash) bejegyzeseit.
//   4. Osszeveti a kettot. Elteres eseten exit 1 - CI gate-nek hasznalhato.
//   5. --manifest: kiir egy JSON ujjlenyomat-manifesztet, amibol a generator
//      logic_hash konstansai frissithetok.
//
// HASZNALAT:
//   node axr-workflow-lint.js <workflow.json> [--manifest out.json]
//
// Nulla kulso fuggoseg - csak a Node beepitett moduljai.
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const crypto = require('crypto');

function sha256hex(s) {
  return 'sha256:' + crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

// A fejlec-verzio kiolvasasa: az ELSO kommentsorokban keresunk vN.N(.N) mintat.
// Csak a kod elso 15 sorat nezzuk, hogy a torzs kozepen levo regi verzio-
// emlitesek (pl. regi changelog-komment) ne zavarjanak be.
function headerVersion(jsCode) {
  const head = jsCode.split('\n').slice(0, 15).join('\n');
  const m = head.match(/v(\d+\.\d+(?:\.\d+)?)/i);
  return m ? m[1] : null;
}

// A generator STEP_NODES blokkjanak kiparszolasa regexszel. Szandekosan nem
// eval: a lint sosem futtathat workflow-kodot. A minta a meglevo node-formara
// illeszkedik:  { node: '...', readFrom: '...', type: '...', logic_version: '...' }
function parseStepNodes(genCode) {
  const block = genCode.match(/STEP_NODES\s*=\s*\[([\s\S]*?)\];/);
  if (!block) return null;
  const entries = [];
  const entryRe = /\{\s*node:\s*'([^']*)'[\s\S]*?logic_version:\s*(?:'([^']*)'|null)(?:[\s\S]*?logic_hash:\s*(?:'([^']*)'|null))?[\s\S]*?\}/g;
  let m;
  while ((m = entryRe.exec(block[1])) !== null) {
    entries.push({ node: m[1], logic_version: m[2] ?? null, logic_hash: m[3] ?? null });
  }
  return entries;
}

function main() {
  const args = process.argv.slice(2);
  const wfPath = args.find(a => !a.startsWith('--'));
  const manifestIdx = args.indexOf('--manifest');
  const manifestPath = manifestIdx >= 0 ? args[manifestIdx + 1] : null;

  if (!wfPath) {
    console.error('Hasznalat: node axr-workflow-lint.js <workflow.json> [--manifest out.json]');
    process.exit(2);
  }

  const wf = JSON.parse(fs.readFileSync(wfPath, 'utf8'));
  const nodes = Object.fromEntries((wf.nodes || []).map(n => [n.name, n]));

  const gen = nodes['AXR Receipt Generator'];
  if (!gen || !gen.parameters || !gen.parameters.jsCode) {
    console.error('HIBA: nincs "AXR Receipt Generator" node a workflow-ban.');
    process.exit(2);
  }
  const declared = parseStepNodes(gen.parameters.jsCode);
  if (!declared) {
    console.error('HIBA: a generator kodjaban nem talalhato STEP_NODES blokk.');
    process.exit(2);
  }

  const manifest = {};
  const problems = [];
  const notices = [];

  for (const d of declared) {
    const node = nodes[d.node];
    if (!node) {
      problems.push(`${d.node}: a generator tanusitja, de a node NINCS a workflow-ban`);
      continue;
    }
    const jsCode = node.parameters && node.parameters.jsCode;
    if (!jsCode) {
      // nem Code node (pl. Google Calendar) - nincs sajat kod, nincs mit driftelni
      manifest[d.node] = { kind: 'external', logic_version: d.logic_version, code_hash: null };
      continue;
    }
    const actualVersion = headerVersion(jsCode);
    const actualHash = sha256hex(jsCode);
    manifest[d.node] = { kind: 'code', header_version: actualVersion, code_hash: actualHash };

    // verzio-osszevetes: a deklaralt '5.0 HU' tipusu ertekbol a szam-reszt nezzuk
    if (d.logic_version !== null) {
      const declaredNum = (d.logic_version.match(/(\d+\.\d+(?:\.\d+)?)/) || [])[1] || null;
      if (actualVersion && declaredNum && actualVersion !== declaredNum) {
        problems.push(
          `${d.node}: a kod fejlece v${actualVersion}, a generator logic_version='${d.logic_version}' - ` +
          `a receiptek HAMIS logika-verziot tanusitanak`);
      } else if (!actualVersion) {
        notices.push(`${d.node}: nincs felismerheto verzio a kod fejleceben (elso 15 sor)`);
      }
    } else {
      notices.push(`${d.node}: a generator logic_version=null - kod-node-nal erdemes verziot adni`);
    }

    // hash-osszevetes, ha a generator mar hordoz logic_hash-t
    if (d.logic_hash && d.logic_hash !== actualHash) {
      problems.push(
        `${d.node}: a kod ujjlenyomata ${actualHash.slice(0, 23)}..., a generator logic_hash=` +
        `${d.logic_hash.slice(0, 23)}... - a kod valtozott a generator frissitese nelkul`);
    }
  }

  // riport
  console.log(`AXR workflow lint - ${wf.name || wfPath}`);
  console.log(`Tanusitott node-ok: ${declared.length}\n`);
  for (const [name, info] of Object.entries(manifest)) {
    const v = info.header_version ? `v${info.header_version}` : (info.kind === 'external' ? '(external)' : 'v?');
    const h = info.code_hash ? info.code_hash.slice(0, 23) + '...' : '-';
    console.log(`  ${name.padEnd(28)} ${v.padEnd(12)} ${h}`);
  }
  console.log('');
  for (const n of notices) console.log(`  NOTICE  ${n}`);
  for (const p of problems) console.log(`  PROBLEM ${p}`);

  if (manifestPath) {
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n', 'utf8');
    console.log(`\nManifeszt kiirva: ${manifestPath}`);
  }

  if (problems.length > 0) {
    console.log(`\nFAIL - ${problems.length} drift-problema. A generator STEP_NODES tablaja frissitendo.`);
    process.exit(1);
  }
  console.log('\nOK - a generator es a workflow-kod szinkronban van.');
  process.exit(0);
}

main();
