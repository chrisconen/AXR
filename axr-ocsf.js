// ═══════════════════════════════════════════════════════════════════════════════
// AXR - OCSF Detection Finding mapping (0.5+)
// ═══════════════════════════════════════════════════════════════════════════════
// A monitor sertesei/jelzesei onmagukban csak az AXR vilagaban ertelmezhetok.
// Ahhoz, hogy egy SOC/SIEM (Splunk, Sentinel, Security Lake) fogyassza oket,
// szabvanyos formara kell kepezni: az OCSF (Open Cybersecurity Schema
// Framework) Detection Finding osztalyara (class_uid 2004, category Findings).
//
// A mapping-tabla a ket 0.5-os kulcs-kod letezesere epul: a KEY_ROTATED_
// AUTHORIZED informacios szintu (a rotacio legitim, de a SOC tudni akarja),
// a KEY_CHANGED_UNAUTHORIZED kritikus. Igy a kulcs-eletciklus eszlelheto
// esemenny valik, nem csak logsorra.
//
// OSZINTE HATAR: a kimenet az OCSF 1.1.0 Detection Finding ALAKJAT koveti
// (a kotelezo mezokkel); formalis OCSF-validacion/tanusitason nem ment at.
// Az AXR-specifikus reszletek az 'unmapped.axr' alatt utaznak - ez az OCSF
// altal erre szant hely, semmi nem veszik el a konverzioban.
//
// Determinisztikus finding-uid: sha256 a (log_id, code, message) kanonikus
// formaja folott - ugyanaz a serles ket pollban ugyanazt az uid-t adja, igy
// a SIEM oldali deduplikacio mukodik. Tradeoff (kimondva): a dedup message-
// fuggo - ha egy uzenetszoveg valtozik (pl. kod-modositas), ugyanaz az ok uj
// uid-t kap. Ez a biztonsagos irany: inkabb ket finding egy okrol, mint ket
// kulonbozo ok osszevonva.
//
// Nulla kulso fuggoseg - csak a kozos axr-core.js.
// ═══════════════════════════════════════════════════════════════════════════════

const core = require('./axr-core');

const OCSF_VERSION = '1.1.0';
const SEVERITY_NAMES = ['Unknown', 'Informational', 'Low', 'Medium', 'High', 'Critical', 'Fatal'];

// ── A mapping-tabla ────────────────────────────────────────────────────────────
// severity_id (OCSF): 1 Informational, 2 Low, 3 Medium, 4 High, 5 Critical.
// A 'kind' azt mondja meg, honnan jon a kod: violation (sertes) vagy notice
// (jelzes-prefix). Ismeretlen VIOLATION kod -> High (fail-closed: ami sertes,
// az akkor is sulyos, ha a tabla meg nem ismeri); ismeretlen notice -> kimarad.
const MAPPING = {
  // sertesek (violation -> mindig finding)
  EQUIVOCATION:             { severity_id: 5, title: 'AXR equivocation: az operator ket kulonbozo fat mutatott' },
  NON_APPEND_ONLY:          { severity_id: 5, title: 'AXR non-append-only: a multat atirtak (consistency proof bukott)' },
  TRUNCATION:               { severity_id: 5, title: 'AXR truncation: a log zsugorodott vagy kiurult' },
  KEY_CHANGED_UNAUTHORIZED: { severity_id: 5, title: 'AXR kulcsvaltas root-autorizacio NELKUL' },
  KEY_REVOKED:              { severity_id: 5, title: 'AXR revokalt kulccsal alairt artefaktum a hatar utan' },
  TRUST_ROOT_INVALID:       { severity_id: 5, title: 'AXR trust-root ervenytelen (fail-closed)' },
  TRUST_ROOT_CHANGED:       { severity_id: 5, title: 'AXR pinned genesis trust-root csere kiserlet' },
  CONTROL_WITHHELD:         { severity_id: 5, title: 'AXR control-log visszatartas (commitolt governance-keszlet hianyzik)' },
  CONTROL_NON_APPEND_ONLY:  { severity_id: 5, title: 'AXR control-log zsugorodas/atiras (nem append-only)' },
  CONTROL_DOWNGRADE:        { severity_id: 5, title: 'AXR control-commitment elhagyas (revokacio-rejtes kiserlet)' },
  CONTROL_ROOT_MISMATCH:    { severity_id: 4, title: 'AXR control-commitment nem egyezik a publikalt control loggal' },
  REVOCATION_UNAUTHORIZED:  { severity_id: 4, title: 'AXR ervenytelen/jogosulatlan revokacios rekord' },
  ROOT_MISMATCH:            { severity_id: 4, title: 'AXR root mismatch: az STH nem a tenyleges receiptek gyokere' },
  BAD_SIGNATURE:            { severity_id: 4, title: 'AXR ervenytelen STH-alairas' },
  KEY_CHANGED:              { severity_id: 4, title: 'AXR operator-kulcs valtozas (TOFU-pinning mod)' },
  LOG_ID_CHANGED:           { severity_id: 3, title: 'AXR log_id valtozas' },
  // jelzesek (notice-prefix -> csak a biztonsag-relevans eletciklus-esemenyek)
  KEY_ROTATED_AUTHORIZED:   { severity_id: 1, title: 'AXR root-autorizalt kulcsrotacio' },
  DEGRADED:                 { severity_id: 2, title: 'AXR degradalt mod: nincs root-horgonyzott genesis (TOFU)' }
};
const UNKNOWN_VIOLATION = { severity_id: 4, title: 'AXR sertes (a mapping-tabla altal nem ismert kod)' };

// Egy OCSF Detection Finding osszeallitasa egy AXR esemenybol.
function makeFinding(code, message, opts) {
  const map = MAPPING[code] || UNKNOWN_VIOLATION;
  const timeMs = Date.parse((opts.now || (() => new Date().toISOString()))());
  const uid = core.sha256({ log_id: opts.logId || null, code, message });
  return {
    activity_id: 1, activity_name: 'Create',
    category_uid: 2, category_name: 'Findings',
    class_uid: 2004, class_name: 'Detection Finding',
    type_uid: 200401,
    severity_id: map.severity_id,
    severity: SEVERITY_NAMES[map.severity_id],
    status_id: 1, status: 'New',
    time: timeMs,
    message,
    metadata: {
      version: OCSF_VERSION,
      logged_time: timeMs,
      product: { name: 'AXR Monitor', vendor_name: 'Conen Digital', version: opts.productVersion || '0.5.0' }
    },
    finding_info: {
      uid,
      title: map.title,
      desc: message,
      types: ['axr/' + code]
    },
    // minden AXR-specifikus reszlet - az OCSF erre szant helyen, veszteseg nelkul
    unmapped: {
      axr: {
        code,
        log_id: opts.logId || null,
        active_key_fingerprint: opts.activeKeyFingerprint || null,
        journal_max_tree_size: opts.journalMax != null ? opts.journalMax : null
      }
    }
  };
}

// ── Fo belepo: egy pollMonitor-eredmeny -> Detection Finding tomb ──────────────
// A sertesek mindig findingok. A jelzesek kozul csak a mapping-tablaban szereplo
// prefixuek (KEY_ROTATED_AUTHORIZED, DEGRADED) - a tobbi jelzes uzemi zaj lenne
// egy SIEM-ben. Ures tomb = nincs jelentenivalo.
function toDetectionFindings(pollResult, opts) {
  const o = opts || {};
  const ctx = {
    now: o.now,
    productVersion: o.productVersion,
    logId: o.logId != null ? o.logId : (pollResult.logId || null),
    activeKeyFingerprint: pollResult.activeKeyFingerprint || null,
    journalMax: pollResult.journalMax
  };
  const findings = [];
  for (const v of (pollResult.violations || []))
    findings.push(makeFinding(v.code, v.message, ctx));
  for (const n of (pollResult.notices || [])) {
    const m = /^([A-Z_]+):/.exec(String(n));
    if (m && MAPPING[m[1]]) findings.push(makeFinding(m[1], String(n), ctx));
  }
  return findings;
}

module.exports = { toDetectionFindings, MAPPING, OCSF_VERSION, SEVERITY_NAMES };
