#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════════════
// AXR - egysegesitett teszt-futtato (auto-discovery)
// ═══════════════════════════════════════════════════════════════════════════════
// AUTOMATIKUSAN felfedez minden `axr-*-test.js` fajlt a repo gyokereben, lefuttatja
// oket, osszesiti az eredmenyt, es nem-nulla kilepesi kodot ad ha barmelyik bukik.
// Ez a CI (es az `npm test`) egyetlen belepesi pontja.
//
// Miert auto-discovery: egy kezzel karbantartott lista mellett egy ujonnan
// hozzaadott teszt neman kicsuszhat a CI alol (es piros maradhat eszrevetlenul).
// A glob garantalja, hogy minden teszt-fajl resze a "zold" allitasnak - egy
// repo, aminek a hitele a tesztekre epul, ezt nem engedheti meg maskeppen.
//
// A crossverify-test maga inditja a Python verifiert (axr_verify.py), igy a
// JS<->Python paritas is automatikusan resze a futasnak.
// ═══════════════════════════════════════════════════════════════════════════════

const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const SUITES = fs.readdirSync(__dirname)
  .filter(f => /^axr-.*-test\.js$/.test(f))
  .sort((a, b) => {
    // a crossverify (lassu, Python-t indit) fusson utoljara - tisztabb kimenet
    if (a.includes('crossverify')) return 1;
    if (b.includes('crossverify')) return -1;
    return a.localeCompare(b);
  });

if (!SUITES.length) {
  console.error('Nem talalhato egyetlen axr-*-test.js sem.');
  process.exit(2);
}

let failed = 0;
const results = [];

for (const suite of SUITES) {
  process.stdout.write(`\n=== ${suite} ===\n`);
  const res = spawnSync(process.execPath, [path.join(__dirname, suite)], { stdio: 'inherit' });
  const ok = res.status === 0;
  if (!ok) failed++;
  results.push({ suite, ok, code: res.status });
}

console.log('\n' + '='.repeat(72));
console.log(`OSSZEGZES (${results.length} suite auto-felfedezve)`);
console.log('='.repeat(72));
for (const r of results) {
  console.log(`  ${r.ok ? 'OK  ' : 'BUKIK'}  ${r.suite}${r.ok ? '' : ` (exit ${r.code})`}`);
}
console.log('-'.repeat(72));
if (failed === 0) {
  console.log(`Mind a ${results.length} suite zold.`);
  process.exit(0);
} else {
  console.log(`${failed}/${results.length} suite BUKOTT.`);
  process.exit(1);
}
