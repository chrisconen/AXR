#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════════════
// AXR - egysegesitett teszt-futtato
// ═══════════════════════════════════════════════════════════════════════════════
// Lefuttatja az osszes teszt-suite-ot egymas utan, osszesiti az eredmenyt, es
// nem-nulla kilepesi kodot ad ha barmelyik bukik. Ez a CI (es az `npm test`)
// egyetlen belepesi pontja: a "fuggetlen implementaciok egyeznek" allitas csak
// akkor er valamit, ha minden push-nal automatikusan bizonyitott.
//
// A crossverify-test maga inditja a Python verifiert (axr_verify.py), igy a
// JS<->Python paritas is ide tartozik.
// ═══════════════════════════════════════════════════════════════════════════════

const { spawnSync } = require('child_process');
const path = require('path');

const SUITES = [
  'axr-canonical-test.js',
  'axr-test-0.3.js',
  'axr-anchor-test.js',
  'axr-monitor-test.js',
  'axr-generative-test.js',
  'axr-redactable-test.js',
  'axr-sideeffect-test.js',
  'axr-adversarial-test.js',
  'axr-trustroot-test.js',
  'axr-strict-test.js',
  'axr-keysep-test.js',
  'axr-crossverify-test.js'
];

let failed = 0;
const results = [];

for (const suite of SUITES) {
  const file = path.join(__dirname, suite);
  process.stdout.write(`\n=== ${suite} ===\n`);
  const res = spawnSync(process.execPath, [file], { stdio: 'inherit' });
  const ok = res.status === 0;
  if (!ok) failed++;
  results.push({ suite, ok, code: res.status });
}

console.log('\n' + '='.repeat(72));
console.log('OSSZEGZES');
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
