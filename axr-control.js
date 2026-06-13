// ═══════════════════════════════════════════════════════════════════════════════
// AXR 0.7 - Control log (kulcs-governance rekordok in-log, anchorolt terjesztese)
// ═══════════════════════════════════════════════════════════════════════════════
// A 0.6-ban a receipt-role successionok es MINDEN revokacio out-of-band fajlban
// utazik. Ket lyuk marad: (1) withholding - az operator kulonbozo fogyasztoknak
// kulonbozo rekord-keszletet mutathat, mert semmi nem horgonyozza, MELYIK keszlet
// volt ervenyben egy adott fa-meretnel; (2) revokacio-elnyeles - egy kinos
// revokacio "elveszhet" a terjesztesben, eszrevetlenul.
//
// A 0.7 megoldas: a governance-rekordok egy kulon, append-only control.jsonl-ben
// ulnek, es az STH alairt body-ja COMMITOL rajuk: control_root_hash (RFC 6962
// Merkle-gyoker a control-rekordok felett, a meglevo core-gepezettel) +
// control_size. Mivel a signablePart/chainHash nem vagja le, az alairas, a lanc
// es az anchor is fedi - a control-keszlet minden fa-meretnel bizonyithatoan
// rogzitett, es a withholding/elnyeles hangossa valik.
//
// FONTOS: a control log csak a TERJESZTES csatornaja. A rekordok autoritasa
// valtozatlanul a root/kvorum-alairas (axr-succession verifyKeySuccession /
// verifyKeyRevocation). A wire format (receipts.jsonl, LEAF_TYPES, receipt-fa)
// ERINTETLEN - a control log kulon sidecar-fajl, a commitment ket additiv
// STH-mezo.
//
// A control-fa levele a TELJES kanonikus rekord (core.leafHash; a governance-
// rekordoknak nincs anchor_ref/redactable mezojuk, igy az a teljes torzset fedi).
// Az ures fa gyokere a core.merkleRootFromLeaves([]) - igy a "meg nincs
// governance-esemeny" allitas (control_size=0) is bizonyithato.
//
// Nulla kulso fuggoseg - csak a kozos axr-core.js + axr-succession.js.
// ═══════════════════════════════════════════════════════════════════════════════

const core = require('./axr-core');
const succ = require('./axr-succession');

const CONTROL_VERSION = '0.7';
// A control log altal hordozott governance-rekord tipusok. Forward-kompat /
// version-gate elv (0.8): a control log trust-kritikus csatorna, ezert az
// ISMERETLEN record_type FAIL-CLOSED (verifyControlLog elveti). Uj tipus
// felvetele itt tortenik, a fogyasztoi verifikaciojaval egyutt - igy egy regi
// fogyasztó sosem fogad el vakon olyan governance-rekordot, amit nem ert.
// 0.8: witness_set (a witness-kor + threshold deklaracioja, root/kvorum-alairt).
const CONTROL_RECORD_TYPES = ['key_succession', 'key_revocation', 'witness_set'];

// A control-fa Merkle-gyokere egy control-rekord tomb felett (RFC 6962, a
// receipt-fevel azonos gepezet). Ures tomb -> az ures fa gyokere.
function controlRoot(records) {
  return core.merkleRootFromLeaves((records || []).map(core.leafHash));
}

// Egy control-rekord strukturalis + kriptografiai ellenorzese a root-horgonnyal.
// A sidecar EZT futtatja commit elott (Meridian-kikotes: ervenytelen
// governance-anyag NEM anchorolhato), es a fogyasztok is ezt hasznaljak.
//   rootAnchor: PEM | trust-root objektum (single vagy kvorum) | trust-root lanc
//   expectedLogId: ha adott, a rekord log_id-janak egyeznie kell
// -> { ok, problems }
function verifyControlRecord(rec, rootAnchor, expectedLogId) {
  const problems = [];
  if (!rec || typeof rec !== 'object') return { ok: false, problems: ['nem objektum'] };
  if (!CONTROL_RECORD_TYPES.includes(rec.record_type))
    return { ok: false, problems: ['ismeretlen control record_type: ' + rec.record_type] };
  if (expectedLogId != null && rec.log_id !== expectedLogId)
    problems.push('idegen log_id (' + rec.log_id + ' != ' + expectedLogId + ')');
  const anchor = resolveAnchor(rootAnchor);
  if (anchor == null) return { ok: false, problems: problems.concat(['ervenytelen/feloldhatatlan root-horgony']) };
  const v = rec.record_type === 'key_revocation' ? succ.verifyKeyRevocation(rec, anchor)
    : rec.record_type === 'witness_set' ? succ.verifyWitnessSet(rec, anchor)
    : succ.verifyKeySuccession(rec, anchor);
  if (!v.ok) problems.push.apply(problems, v.problems);
  return { ok: problems.length === 0, problems };
}

// Root-horgony feloldasa: PEM marad PEM; egyetlen trust-root marad az; lanc
// (tomb/JSONL) -> az effektiv (utolso, lanc-verifikalt) root. Hiba -> null.
function resolveAnchor(rootAnchor) {
  if (typeof rootAnchor === 'string') return rootAnchor;
  if (Array.isArray(rootAnchor)) {
    const cv = succ.verifyTrustRootChain(rootAnchor);
    return cv.ok ? cv.effective : null;
  }
  if (rootAnchor && rootAnchor.record_type === 'trust_root') return rootAnchor;
  return null;
}

// A teljes control log ellenorzese: minden rekord root-verifikalt es (ha adott)
// log_id-egyezo. -> { ok, problems, valid } (valid: a verifikalt rekordok tombje)
function verifyControlLog(records, rootAnchor, expectedLogId) {
  const problems = [];
  const valid = [];
  (records || []).forEach((rec, i) => {
    const v = verifyControlRecord(rec, rootAnchor, expectedLogId);
    if (v.ok) valid.push(rec);
    else problems.push('control[' + i + ']: ' + v.problems.join('; '));
  });
  return { ok: problems.length === 0, problems, valid };
}

// Egy STH control-commitmentjenek ellenorzese a TENYLEGES control log ellen.
// A commitment ket additiv mezo: control_root_hash + control_size. Szabalyok:
//   - ha az STH nem commitol (egyik mezo sincs), de a fogyasztonal van control
//     log: nem ITT dol el (a downgrade/lag a fogyasztok allapotgepe);
//   - ha commitol: a control_size <= a rendelkezesre allo rekordszam KELL,
//     es az elso control_size rekord gyokere == control_root_hash.
// -> { committed, ok, problems, size }
function checkSthCommitment(sth, records) {
  const hasRoot = sth && typeof sth.control_root_hash === 'string';
  const hasSize = sth && Number.isInteger(sth.control_size);
  if (!hasRoot && !hasSize) return { committed: false, ok: true, problems: [], size: null };
  const problems = [];
  if (hasRoot !== hasSize)
    return { committed: true, ok: false, size: sth.control_size,
             problems: ['hianyos commitment: control_root_hash es control_size egyutt kotelezo'] };
  if (sth.control_size < 0) problems.push('negativ control_size');
  const avail = (records || []).length;
  if (sth.control_size > avail) {
    // WITHHELD-jellegu: a commitolt keszlet nem all rendelkezesre. A vegso
    // osztalyozas (lag vs withheld) a fogyasztoe; itt a tenyt jelezzuk.
    problems.push('a publikalt control log rovidebb (' + avail + '), mint a commitolt control_size (' + sth.control_size + ')');
    return { committed: true, ok: false, size: sth.control_size, problems, withheld: true };
  }
  const recomputed = controlRoot((records || []).slice(0, sth.control_size));
  if (recomputed !== sth.control_root_hash)
    problems.push('control_root_hash nem egyezik az elso ' + sth.control_size + ' control-rekord Merkle-gyokerevel');
  return { committed: true, ok: problems.length === 0, size: sth.control_size, problems };
}

// Ket STH control-commitmentje kozott append-only-e a control log (a meglevo
// consistency-proof gepezettel a control-feval). -> { ok, problems }
// A hivo gondoskodik rola, hogy mindket STH commitoljon (size != null).
function checkControlConsistency(prevSth, curSth, records) {
  const problems = [];
  const m = prevSth.control_size, n = curSth.control_size;
  if (n < m) {
    problems.push('control_size csokkent (' + m + ' -> ' + n + ') - a governance-keszlet zsugorodott');
    return { ok: false, problems };
  }
  if (m === n) {
    if (prevSth.control_root_hash !== curSth.control_root_hash)
      problems.push('azonos control_size (' + m + '), de eltero control_root_hash - a multat atirtak');
    return { ok: problems.length === 0, problems };
  }
  // m < n: a meglevo consistency-proof bizonyitja, hogy az n-fa az m-fa
  // append-only bovitese (a leafHash-eket a tenyleges control logbol szamoljuk)
  if (n <= (records || []).length) {
    const leaves = records.slice(0, n).map(core.leafHash);
    const proof = core.consistencyProof(m, leaves);
    if (!core.verifyConsistency(m, n, prevSth.control_root_hash, curSth.control_root_hash, proof))
      problems.push('control ' + m + ' -> ' + n + ': a consistency proof MEGBUKOTT - a governance-keszlet nem append-only bovites');
  }
  return { ok: problems.length === 0, problems };
}

module.exports = {
  CONTROL_VERSION,
  CONTROL_RECORD_TYPES,
  controlRoot,
  resolveAnchor,
  verifyControlRecord,
  verifyControlLog,
  checkSthCommitment,
  checkControlConsistency
};
