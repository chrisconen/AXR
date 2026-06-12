// ═══════════════════════════════════════════════════════════════════════════════
// AXR - OCSF Detection Finding mapping teszt
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-ocsf-test.js
//
// Mit ellenoriz:
//   1. A ket 0.5-os kulcs-kod helyes szintje: KEY_CHANGED_UNAUTHORIZED ->
//      Critical, KEY_ROTATED_AUTHORIZED -> Informational
//   2. Strukturalis helyesseg: class_uid 2004, category 2, type_uid 200401,
//      kotelezo mezok jelen vannak
//   3. Determinisztikus finding-uid (SIEM-dedup) + AXR-kontextus az unmapped-ben
//   4. Fail-closed: ismeretlen VIOLATION kod -> High; uzemi jelzesek kimaradnak
//
// Nulla kulso fuggoseg.  Kilepesi kod: 0 zold, 1 hiba.
// ═══════════════════════════════════════════════════════════════════════════════

const ocsf = require('./axr-ocsf');

let pass = 0, fail = 0;
function ok(cond, name) { if (cond) { pass++; } else { fail++; console.log('  FAIL: ' + name); } }
function section(t) { console.log('\n' + t); }

const T0 = () => '2026-06-12T10:00:00.000Z';
const LOG = 'axr:ocsf-test:v1';

// Egy tipikus poll-eredmeny: ket sertes + harom jelzes (ebbol egy lifecycle)
const pollResult = {
  ok: false,
  violations: [
    { code: 'KEY_CHANGED_UNAUTHORIZED', message: 'a kulcsvaltas nem root-autorizalt' },
    { code: 'EQUIVOCATION', message: 'ket kulonbozo fa ugyanarra a tree_size-ra' }
  ],
  notices: [
    'KEY_ROTATED_AUTHORIZED: root-autorizalt kulcsvaltas effective_from=4',
    'DEGRADED: a trust-root nem tartalmaz sth-genesis kulcsot',
    'ANCHOR_UNVERIFIED: local anchor - offline mod' // uzemi zaj, NEM lifecycle
  ],
  witnessedCount: 2, journalMax: 6, logId: LOG,
  activeKeyFingerprint: 'sha256:abc'
};

// ───────────────────────────────────────────────────────────────────────────
section('1. A ket kulcs-kod szintje + jelzes-szures');
const f = ocsf.toDetectionFindings(pollResult, { now: T0 });
ok(f.length === 4, '2 sertes + 2 lifecycle-jelzes = 4 finding (az uzemi zaj kimarad), kapott: ' + f.length);
const byCode = {};
for (const x of f) byCode[x.unmapped.axr.code] = x;
ok(byCode.KEY_CHANGED_UNAUTHORIZED && byCode.KEY_CHANGED_UNAUTHORIZED.severity_id === 5,
  'KEY_CHANGED_UNAUTHORIZED -> Critical (5)');
ok(byCode.KEY_ROTATED_AUTHORIZED && byCode.KEY_ROTATED_AUTHORIZED.severity_id === 1,
  'KEY_ROTATED_AUTHORIZED -> Informational (1)');
ok(byCode.EQUIVOCATION && byCode.EQUIVOCATION.severity_id === 5, 'EQUIVOCATION -> Critical (5)');
ok(byCode.DEGRADED && byCode.DEGRADED.severity_id === 2, 'DEGRADED -> Low (2)');

// ───────────────────────────────────────────────────────────────────────────
section('2. Strukturalis helyesseg (OCSF Detection Finding alak)');
const d = byCode.KEY_CHANGED_UNAUTHORIZED;
ok(d.class_uid === 2004 && d.category_uid === 2 && d.type_uid === 200401,
  'class_uid/category_uid/type_uid helyes');
ok(d.activity_id === 1 && d.status_id === 1, 'activity=Create, status=New');
ok(d.severity === 'Critical', 'severity nev konzisztens a severity_id-vel');
ok(typeof d.time === 'number' && d.time === Date.parse(T0()), 'time = epoch ms a now()-bol');
ok(d.metadata && d.metadata.version === ocsf.OCSF_VERSION && d.metadata.product.name === 'AXR Monitor',
  'metadata.version + product jelen');
ok(d.finding_info && d.finding_info.title && d.finding_info.desc === d.message &&
   Array.isArray(d.finding_info.types) && d.finding_info.types[0] === 'axr/KEY_CHANGED_UNAUTHORIZED',
  'finding_info.title/desc/types jelen');

// ───────────────────────────────────────────────────────────────────────────
section('3. Determinisztikus uid + AXR-kontextus');
const f2 = ocsf.toDetectionFindings(pollResult, { now: () => '2026-06-13T00:00:00.000Z' });
ok(f2[0].finding_info.uid === f[0].finding_info.uid,
  'ugyanaz a sertes masik pollban -> azonos uid (SIEM-dedup)');
const other = ocsf.toDetectionFindings({ ...pollResult,
  violations: [{ code: 'KEY_CHANGED_UNAUTHORIZED', message: 'MASIK uzenet' }], notices: [] }, { now: T0 });
ok(other[0].finding_info.uid !== f[0].finding_info.uid, 'mas uzenet -> mas uid');
ok(d.unmapped.axr.log_id === LOG && d.unmapped.axr.active_key_fingerprint === 'sha256:abc' &&
   d.unmapped.axr.journal_max_tree_size === 6, 'AXR-kontextus az unmapped.axr alatt');

// ───────────────────────────────────────────────────────────────────────────
section('4. Fail-closed: ismeretlen sertes-kod -> High');
const unk = ocsf.toDetectionFindings({ ok: false,
  violations: [{ code: 'FUTURE_CODE_X', message: 'uj kod, amit a tabla meg nem ismer' }],
  notices: [], journalMax: 0, logId: LOG }, { now: T0 });
ok(unk.length === 1 && unk[0].severity_id === 4,
  'ismeretlen VIOLATION kod -> High (4), nem esik ki es nem Informational');
const clean = ocsf.toDetectionFindings({ ok: true, violations: [], notices: ['nincs STH a fajlban'],
  journalMax: 0, logId: LOG }, { now: T0 });
ok(clean.length === 0, 'tiszta poll + uzemi jelzes -> nincs finding');

console.log(`\nOsszesen: ${pass} ok, ${fail} hiba`);
process.exit(fail ? 1 : 0);
