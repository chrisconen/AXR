// ═══════════════════════════════════════════════════════════════════════════════
// AXR 0.5 - Operator-kulcs utodlas (key succession)
// ═══════════════════════════════════════════════════════════════════════════════
// A 0.3/0.4 monitor EGY operator-kulcsot pinnel, es minden STH-t azzal verifikal.
// A kulcsrotaciot megkulonboztethetetlenne teszi a csendes kulcscseretol -> minden
// valtozas gyanus. A 0.5 ezt oldja fel: a bizalmi horgony NEM az operator-kulcs
// (epp az rotalodhat), hanem a FUGGETLEN root-kulcs (ugyanaz, ami a trust-rootot
// alairja). Az operator minden kulcsa ebbol szarmaztatott/autorizalt.
//
// Lanc:  root-kulcs (pinned) -> alairja a successiont -> a succession autorizalja
//        az utod kulcsot -> az utod kulcs alairja az STH-t / receiptet.
//
// Genesis: az elso kulcsot NEM succession hozza letre (azt barki mintazhatna),
// hanem a kibovitett trust-root deklaralja (per log_id, per role). Igy a
// kiindulopont is root-horgonyzott - nincs TOFU-gyengeseg.
//
// Role-szeparacio: role='sth' a Signed-Tree-Head alairo kulcs (monitor fogyasztja),
// role='receipt' a receipt-alairo kulcs (verifier fogyasztja). Ugyanaz a formatum.
//
// Egyetlen ora: a tree_size az autoritativ sorrend (Merkle-pozicio, nem hamisithato
// az operator altal). A wall-clock issued_at csak informativ. NINCS not_before/
// not_after (operator-kontrollalt orat nem teszunk a bizalmi utba).
//
// Hatar-szabaly (off-by-one rogzitve): az utod a tree_size >= effective_from_tree_size
// STH-kat irja ala; a megelozo a tree_size < effective_from STH-kat.
//
// Nulla kulso fuggoseg - csak a Node beepitett crypto + a kozos axr-core.js.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const core = require('./axr-core');

const SUCCESSION_VERSION = '0.5';
const ROLES = ['sth', 'receipt'];

// ── Kulcs-fingerprint (a monitor keyFingerprint-jevel BYTE-AZONOS) ─────────────
// A PEM-fejlec nelkuli, whitespace-mentes torzs sha256-ja. Igy egy kulcs
// fingerprintje fuggetlen a PEM sortoresektol/formazastol.
function keyFingerprint(pem) {
  const body = String(pem).replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  return 'sha256:' + crypto.createHash('sha256').update(body, 'utf8').digest('hex');
}

// ═══════════════════════════════════════════════════════════════════════════════
// 0.6 - Kvorum-root (M-of-N multi-alairas)
// ═══════════════════════════════════════════════════════════════════════════════
// A 0.5 root-kulcsa single point of failure: ellopva hamis successionok,
// elveszitve nincs tobb autorizalt rotacio. A 0.6 ezt M-of-N multi-alairassal
// oldja: a trust root `root_keys` listat es `threshold`-ot deklaral, es egy
// rekord akkor ervenyes, ha ugyanazon kanonikus body felett M KULONBOZO
// deklaralt kulcs Ed25519-alairasa all. SZANDEKOSAN nem threshold-kriptografia
// (BLS/FROST fuggoseget hozna): a policy-celt a multi-alairas eleri.
//
// OSZINTEN: a root-kompromittalas lehetosege nem szunik meg - a failure mode
// valtozik: single-key compromise -> kvorum-kompromittalas / collusion /
// policy-hiba / kulcs-kolokacio. A spec kvorum-policy szekcioja reszletezi.
//
// Determinisztikus alairas-keszlet: a `signatures` tomb key_fingerprint
// szerint SZIGORUAN novekvo - az assemble igy rendez, a verify ki is
// kenyszeriti. Ket azonos alairas-halmaz igy byte-azonos rekordot ad
// (a fogyasztok pool-dedupja es lanc-hashe stabil marad).
//
// Az alairt uzenet: canonicalize(rekord a 'signatures' mezo NELKUL). A legacy
// 'signature' mezo - ha valaki utolag biggyesztene ra - resze a body-nak,
// tehat a kvorum-alairasok fedik: utolagos hozzaadasa torik.

// Egy alairo reszalairasa egy (meg alairas nelkuli) body folott.
// -> { key_fingerprint, signature }
function signQuorumPart(body, privPem) {
  if (body && (body.signatures !== undefined))
    throw new Error('signQuorumPart: a body mar tartalmaz signatures mezot');
  const priv = crypto.createPrivateKey(privPem);
  const pubPem = crypto.createPublicKey(priv).export({ type: 'spki', format: 'pem' });
  return {
    key_fingerprint: keyFingerprint(pubPem),
    signature: crypto.sign(null, Buffer.from(core.canonicalize(body), 'utf8'), priv).toString('base64')
  };
}

// Reszalairasok osszefesulese egy kvorum-alairt rekordda. Determinisztikus
// (fingerprint szerint rendez); duplikalt alairo = hiba (fail-closed mar itt).
function assembleQuorum(body, parts) {
  const seen = new Set();
  for (const p of (parts || [])) {
    if (!p || !p.key_fingerprint || !p.signature) throw new Error('assembleQuorum: hianyos reszalairas');
    if (seen.has(p.key_fingerprint)) throw new Error('assembleQuorum: duplikalt alairo ' + p.key_fingerprint.slice(0, 20) + '...');
    seen.add(p.key_fingerprint);
  }
  const sorted = (parts || []).slice().sort((a, b) =>
    a.key_fingerprint < b.key_fingerprint ? -1 : a.key_fingerprint > b.key_fingerprint ? 1 : 0);
  return { ...body, signatures: sorted };
}

// Kvorum-ellenorzes: a rekord `signatures` tombje eleri-e a threshold-ot a
// deklaralt kulcskeszletbol. SZIGORU fail-closed (Meridian-invarians): BARMELY
// anomalia - duplikalt alairo, nem-deklaralt kulcs, ervenytelen alairas,
// rendezetlen sorrend - elutasitast jelent, akkor is, ha a kvorum egyebkent
// meglenne. Egy tiszta kvorum-rekordban nincs helye szemetnek.
// -> { ok, problems, validSigners }
function verifyQuorumSigned(record, declaredPems, threshold) {
  const problems = [];
  if (!record || !Array.isArray(record.signatures) || !record.signatures.length)
    return { ok: false, problems: ['hianyzo/ures signatures (kvorum-alairas)'], validSigners: 0 };
  const byFp = new Map();
  for (const pem of (declaredPems || [])) byFp.set(keyFingerprint(pem), pem);
  const body = { ...record };
  delete body.signatures;
  const msg = Buffer.from(core.canonicalize(body), 'utf8');
  let valid = 0;
  let prevFp = null;
  for (const part of record.signatures) {
    if (!part || !part.key_fingerprint || !part.signature) { problems.push('hianyos alairas-bejegyzes'); continue; }
    if (prevFp !== null && !(part.key_fingerprint > prevFp))
      problems.push('nem-determinisztikus alairas-sorrend (nem szigoruan novekvo fingerprint): ' + part.key_fingerprint.slice(0, 20) + '...');
    prevFp = part.key_fingerprint;
    const pem = byFp.get(part.key_fingerprint);
    if (!pem) { problems.push('nem-deklaralt alairo: ' + part.key_fingerprint.slice(0, 20) + '...'); continue; }
    try {
      const ok = crypto.verify(null, msg, crypto.createPublicKey(pem), Buffer.from(part.signature, 'base64'));
      if (ok) valid++;
      else problems.push('ERVENYTELEN alairas a(z) ' + part.key_fingerprint.slice(0, 20) + '... alairotol');
    } catch (e) { problems.push('alairas-ellenorzes hiba (' + part.key_fingerprint.slice(0, 20) + '...): ' + e.message); }
  }
  if (valid < threshold)
    problems.push('kvorum NEM teljesul: ' + valid + ' ervenyes alairas < threshold ' + threshold);
  return { ok: valid >= threshold && problems.length === 0, problems, validSigners: valid };
}

// A trust root modjanak felismerese. Pontosan EGY mod lehet ervenyes.
// -> { mode: 'single'|'quorum'|'invalid', keys, threshold, problems }
function trustRootMode(tr) {
  const hasSingle = !!(tr && tr.root_public_key);
  const hasQuorum = !!(tr && (Array.isArray(tr.root_keys) || tr.threshold != null));
  if (hasSingle && hasQuorum)
    return { mode: 'invalid', problems: ['vegyes mod: root_public_key ES root_keys/threshold egyszerre'] };
  if (hasQuorum) {
    const problems = [];
    if (!Array.isArray(tr.root_keys) || !tr.root_keys.length) problems.push('ures/hianyzo root_keys');
    const n = Array.isArray(tr.root_keys) ? tr.root_keys.length : 0;
    if (!Number.isInteger(tr.threshold) || tr.threshold < 1 || tr.threshold > n)
      problems.push('ervenytelen threshold (1..' + n + ' kell legyen): ' + tr.threshold);
    if (problems.length) return { mode: 'invalid', problems };
    return { mode: 'quorum', keys: tr.root_keys, threshold: tr.threshold, problems: [] };
  }
  if (hasSingle) return { mode: 'single', keys: [tr.root_public_key], threshold: 1, problems: [] };
  return { mode: 'invalid', problems: ['hianyzo root_public_key vagy root_keys/threshold'] };
}

// ── Genesis-tartalmu trust-root epitese (0.5) ─────────────────────────────────
// A 0.4 trust-root provider-kulcsokat deklaral; a 0.5 ezt kiegesziti a logok
// genesis operator-kulcsaival. Egyetlen root-kulcs alairja mindkettot.
//   providers: [ { provider, public_keys:[pem] } ]            (0.4-bol valtozatlan)
//   logs:      [ { log_id, genesis: { sth: pem, receipt: pem } } ]   (0.5 uj)
// A kozos (mod-fuggetlen) body-resz. 0.6: ha opts.root_keys/threshold van,
// kvorum-modu body keszul (root_public_key NELKUL) - azt a kvorum irja ala.
function buildTrustRootBody(opts, now) {
  const body = {
    axr_version: SUCCESSION_VERSION,
    record_type: 'trust_root',
    issued_at: (now || (() => new Date().toISOString()))(),
    providers: (opts.providers || []).map(p => ({
      provider: p.provider,
      public_keys: (p.public_keys || []).slice()
    })),
    logs: (opts.logs || []).map(l => ({
      log_id: l.log_id,
      genesis: {
        sth: (l.genesis && l.genesis.sth) || null,
        receipt: (l.genesis && l.genesis.receipt) || null
      }
    }))
  };
  if (opts.root_keys || opts.threshold != null) {
    if (!Array.isArray(opts.root_keys) || !opts.root_keys.length)
      throw new Error('buildTrustRootBody: root_keys nem-ures tomb kell legyen');
    if (!Number.isInteger(opts.threshold) || opts.threshold < 1 || opts.threshold > opts.root_keys.length)
      throw new Error('buildTrustRootBody: threshold 1..' + opts.root_keys.length + ' kell legyen');
    body.root_keys = opts.root_keys.slice();
    body.threshold = opts.threshold;
  }
  return body;
}

function buildTrustRoot(opts, rootPrivPem, rootPubPem, now) {
  const body = buildTrustRootBody(opts, now);
  if (body.root_keys)
    throw new Error('buildTrustRoot: kvorum-modu trust roothoz buildQuorumTrustRoot kell');
  body.root_public_key = rootPubPem;
  const sig = crypto.sign(null, Buffer.from(core.canonicalize(body), 'utf8'),
    crypto.createPrivateKey(rootPrivPem)).toString('base64');
  return { ...body, signature: sig };
}

// Kenyelmi epito tesztekhez / egy-gepes ceremoniahoz: minden privat kulcs
// helyben van. A valodi tobb-gepes folyamat a CLI sign/assemble utjan megy
// (a body-t kulon gepeken irjak ala, a reszek utana fesulodnek ossze).
function buildQuorumTrustRoot(opts, signerPrivPems, now) {
  const body = buildTrustRootBody(opts, now);
  if (!body.root_keys) throw new Error('buildQuorumTrustRoot: opts.root_keys + opts.threshold kotelezo');
  const parts = (signerPrivPems || []).map(p => signQuorumPart(body, p));
  return assembleQuorum(body, parts);
}

// A trust-root integritas-ellenorzese: egykulcsos modban a sajat
// root_public_key-evel, kvorum-modban (0.6) a deklaralt root_keys
// M-of-N kvorumaval verifikal-e. -> { ok, problems }
function verifyTrustRoot(trustRoot) {
  const problems = [];
  if (!trustRoot || typeof trustRoot !== 'object') return { ok: false, problems: ['nem objektum'] };
  if (trustRoot.record_type !== 'trust_root') problems.push('record_type != trust_root');
  const m = trustRootMode(trustRoot);
  if (m.mode === 'invalid') return { ok: false, problems: problems.concat(m.problems) };
  if (m.mode === 'quorum') {
    const q = verifyQuorumSigned(trustRoot, m.keys, m.threshold);
    return { ok: problems.length === 0 && q.ok, problems: problems.concat(q.problems) };
  }
  if (!trustRoot.signature) problems.push('hianyzo signature');
  if (problems.length) return { ok: false, problems };
  const body = { ...trustRoot }; delete body.signature;
  try {
    const ok = crypto.verify(null, Buffer.from(core.canonicalize(body), 'utf8'),
      crypto.createPublicKey(trustRoot.root_public_key),
      Buffer.from(trustRoot.signature, 'base64'));
    if (!ok) problems.push('a trust-root alairasa ERVENYTELEN');
  } catch (e) { problems.push('trust-root alairas-ellenorzes hiba: ' + e.message); }
  return { ok: problems.length === 0, problems };
}

// ═══════════════════════════════════════════════════════════════════════════════
// 0.6 - Root-rotacio / recovery (trust-root lanc)
// ═══════════════════════════════════════════════════════════════════════════════
// A root-keszlet maga is rotalhato: egy UTOD trust-rootot az ELOD deklaralt
// kulcskeszletenek M-of-N kvoruma ir ala, es predecessor_trust_root_hash
// lancolja az elodhoz. A fogyasztok a pinned lanc-fejtol (genesis) kovetik a
// lancot; az "effektiv" root a lanc utolso eleme. Recovery: amig M alairo
// megvan az N-bol, a kvorum uj keszletet autorizal - in-protocol. Ha M-nel
// kevesebb maradt: out-of-band uj trust root (kimondva, mint eddig).
//
// Egy 0.5-os egykulcsos root is rotalhat kvorum-utodra (migracio): az elod
// modja szerint verifikalunk (single = 1-of-1 kvorum). Az utod-rekord NEM
// ervenyes onmagaban (a sajat kulcsai nem irtak ala) - CSAK lancban, a pinned
// fejtol levezetve. Ez szandekos: nincs onmagat autorizalo root.

// Utod trust-root epitese: az uj body-t (uj kulcskeszlet/genesisek) az ELOD
// alairoinak reszalairasai fedik. opts mint buildTrustRootBody +
// opcionalisan root_public_key (single-modu utodhoz).
function buildTrustRootSuccessor(opts, predecessor, oldSignerPrivPems, now) {
  const body = buildTrustRootBody(opts, now);
  if (!body.root_keys) {
    if (!opts.root_public_key) throw new Error('buildTrustRootSuccessor: root_keys+threshold VAGY root_public_key kell');
    body.root_public_key = opts.root_public_key;
  }
  body.predecessor_trust_root_hash = core.sha256(predecessor);
  const parts = (oldSignerPrivPems || []).map(p => signQuorumPart(body, p));
  return assembleQuorum(body, parts);
}

// Trust-root lanc ellenorzese. records: a pinned genesis-tol az aktualisig.
// -> { ok, problems, effective } - az effective a lanc utolso eleme (csak ok
// eseten). Fail-closed: barmely lancszem-hiba a teljes lancot erventeleniti.
function verifyTrustRootChain(records) {
  const problems = [];
  if (!Array.isArray(records) || !records.length)
    return { ok: false, problems: ['ures trust-root lanc'], effective: null };
  // 1. a lanc feje: onmagaban ervenyes (pinned) genesis
  const head = records[0];
  const headChk = verifyTrustRoot(head);
  if (!headChk.ok)
    return { ok: false, problems: ['a lanc-fej (pinned genesis) ervenytelen: ' + headChk.problems.join('; ')], effective: null };
  if (head.predecessor_trust_root_hash)
    problems.push('a lanc-fej predecessor_trust_root_hash-t hordoz - nem genesis');
  // 2. minden utod: elod-hash lancolas + az ELOD kvoruma autorizal
  for (let i = 1; i < records.length; i++) {
    const prev = records[i - 1], cur = records[i];
    if (!cur || cur.record_type !== 'trust_root') { problems.push('a(z) ' + i + '. lancszem nem trust_root'); continue; }
    if (cur.predecessor_trust_root_hash !== core.sha256(prev))
      problems.push('lanc-tores a(z) ' + i + '. elemnel: predecessor_trust_root_hash nem az elozo rekordra mutat');
    const pm = trustRootMode(prev);
    const q = verifyQuorumSigned(cur, pm.keys, pm.threshold);
    if (!q.ok)
      problems.push('a(z) ' + i + '. utod-root NEM az elod kvorumaval alairt: ' + q.problems.join('; '));
    const cm = trustRootMode(cur);
    if (cm.mode === 'invalid')
      problems.push('a(z) ' + i + '. utod-root sajat kulcs-deklaracioja ervenytelen: ' + cm.problems.join('; '));
  }
  return { ok: problems.length === 0, problems, effective: problems.length === 0 ? records[records.length - 1] : null };
}

// Trust-root bemenet normalizalasa: egyetlen rekord, rekord-tomb vagy JSONL
// szoveg -> rekordlista. A fogyasztok (monitor, verifierek) ezt hasznaljak,
// igy a --trust-root fajl maradhat egyrekordos (0.5) vagy lehet lanc (0.6).
function parseTrustRootInput(input) {
  if (Array.isArray(input)) return input;
  if (input && typeof input === 'object') return [input];
  const text = String(input).trim();
  try {
    const parsed = JSON.parse(text);
    return Array.isArray(parsed) ? parsed : [parsed];
  } catch (e) {
    return text.split('\n').filter(Boolean).map(l => JSON.parse(l));
  }
}

// A genesis-kulcs kinyerese egy (mar verifikalt) trust-rootbol.
function genesisKey(trustRoot, logId, role) {
  if (!trustRoot || !Array.isArray(trustRoot.logs)) return null;
  const l = trustRoot.logs.find(x => x && x.log_id === logId);
  if (!l || !l.genesis) return null;
  return l.genesis[role] || null;
}

// ── Succession-rekord epitese (root-alairt) ───────────────────────────────────
//   opts: { log_id, role, predecessor_fingerprint, successor_public_key,
//           effective_from_tree_size, reason }
// A predecessor_fingerprint SOHA nem null (a genesis a trust-rootbol jon).
function buildKeySuccessionBody(opts, now) {
  if (!ROLES.includes(opts.role)) throw new Error('ervenytelen role: ' + opts.role);
  if (!opts.predecessor_fingerprint) throw new Error('predecessor_fingerprint kotelezo (genesis a trust-rootbol jon)');
  if (!opts.successor_public_key) throw new Error('successor_public_key kotelezo');
  if (!Number.isInteger(opts.effective_from_tree_size) || opts.effective_from_tree_size < 1)
    throw new Error('effective_from_tree_size pozitiv egesz kell legyen');
  return {
    axr_version: SUCCESSION_VERSION,
    record_type: 'key_succession',
    log_id: opts.log_id,
    role: opts.role,
    predecessor_fingerprint: opts.predecessor_fingerprint,
    successor_public_key: opts.successor_public_key,
    successor_fingerprint: keyFingerprint(opts.successor_public_key),
    effective_from_tree_size: opts.effective_from_tree_size,
    reason: opts.reason || 'unspecified',
    issued_at: (now || (() => new Date().toISOString()))()
  };
}

function buildKeySuccession(opts, rootPrivPem, now) {
  const body = buildKeySuccessionBody(opts, now);
  const sig = crypto.sign(null, Buffer.from(core.canonicalize(body), 'utf8'),
    crypto.createPrivateKey(rootPrivPem)).toString('base64');
  return { ...body, signature: sig };
}

// Kenyelmi epito kvorum-alairt successionhez (egy-gepes ceremonia / teszt).
function buildQuorumKeySuccession(opts, signerPrivPems, now) {
  const body = buildKeySuccessionBody(opts, now);
  const parts = (signerPrivPems || []).map(p => signQuorumPart(body, p));
  return assembleQuorum(body, parts);
}

// ── Succession-rekord ellenorzese a ROOT-horgonnyal ───────────────────────────
// -> { ok, problems }. Strukturalis + alairas + fingerprint-konzisztencia.
// rootAnchor: PEM string (0.5, egykulcsos) VAGY trust-root objektum (0.6) -
// utobbinal a trust root modja dont: single -> root_public_key, quorum ->
// M-of-N a deklaralt root_keys-bol. A trust-root sajat integritasat a hivo
// mar ellenorizte (verifyTrustRoot) - itt csak a modjat hasznaljuk.
function verifyKeySuccession(succ, rootAnchor) {
  const problems = [];
  if (!succ || typeof succ !== 'object') return { ok: false, problems: ['nem objektum'] };
  if (succ.record_type !== 'key_succession') problems.push('record_type != key_succession');
  if (!ROLES.includes(succ.role)) problems.push('ervenytelen role');
  if (!succ.predecessor_fingerprint) problems.push('hianyzo predecessor_fingerprint');
  if (!succ.successor_public_key) problems.push('hianyzo successor_public_key');
  if (!Number.isInteger(succ.effective_from_tree_size) || succ.effective_from_tree_size < 1)
    problems.push('ervenytelen effective_from_tree_size');
  if (problems.length) return { ok: false, problems };
  // a deklaralt successor_fingerprint tenyleg a megadott kulcse?
  if (succ.successor_fingerprint !== keyFingerprint(succ.successor_public_key))
    problems.push('successor_fingerprint nem egyezik a successor_public_key-vel');

  // alairas-ut kivalasztasa a horgony tipusa szerint
  let mode = null;
  if (typeof rootAnchor === 'string') mode = { mode: 'single', keys: [rootAnchor], threshold: 1 };
  else if (rootAnchor && rootAnchor.record_type === 'trust_root') {
    mode = trustRootMode(rootAnchor);
    if (mode.mode === 'invalid') return { ok: false, problems: problems.concat(mode.problems) };
  } else return { ok: false, problems: problems.concat(['ervenytelen root-horgony (PEM vagy trust-root objektum kell)']) };

  if (mode.mode === 'quorum') {
    const q = verifyQuorumSigned(succ, mode.keys, mode.threshold);
    return { ok: problems.length === 0 && q.ok, problems: problems.concat(q.problems) };
  }
  if (!succ.signature) return { ok: false, problems: problems.concat(['hianyzo signature']) };
  const body = { ...succ }; delete body.signature;
  try {
    const ok = crypto.verify(null, Buffer.from(core.canonicalize(body), 'utf8'),
      crypto.createPublicKey(mode.keys[0]), Buffer.from(succ.signature, 'base64'));
    if (!ok) problems.push('a succession alairasa ERVENYTELEN a root-kulcsra');
  } catch (e) { problems.push('succession alairas-ellenorzes hiba: ' + e.message); }
  return { ok: problems.length === 0, problems };
}

// ═══════════════════════════════════════════════════════════════════════════════
// 0.6 - Revokacio (key_revocation)
// ═══════════════════════════════════════════════════════════════════════════════
// A succession elore-rotal; a revokacio a kulcs alairo erejet vonja vissza egy
// tree_size hatartol. Szemantika (3-szintu szabaly, a 0.6 scope-dontes szerint):
//   - revoked_at ELOTTI pozicio + anchorolt bizonyitek -> ervenyes marad
//     (a mar tanusitott mult nem irodik at);
//   - revoked_at elotti pozicio bizonyitek NELKUL -> fail-closed (lopott regi
//     kulccsal nem gyarthato utolagos pre-boundary narrativa);
//   - revoked_at utani pozicio -> KEY_REVOKED.
// A "mikor tudtuk meg" wall-clock kerdese NEM resze a bizalmi utnak: a hatar
// a revoked_at_tree_size. A bizonyitek-kovetelmenyt a fogyasztok (verifier:
// anchor_ref + inclusion proof; monitor: a journal + STH-folyam) ervenyesitik.

const REVOCATION_VERSION = '0.6';

function buildKeyRevocationBody(opts, now) {
  if (!ROLES.includes(opts.role)) throw new Error('ervenytelen role: ' + opts.role);
  if (!opts.revoked_fingerprint) throw new Error('revoked_fingerprint kotelezo');
  if (!Number.isInteger(opts.revoked_at_tree_size) || opts.revoked_at_tree_size < 1)
    throw new Error('revoked_at_tree_size pozitiv egesz kell legyen');
  return {
    axr_version: REVOCATION_VERSION,
    record_type: 'key_revocation',
    log_id: opts.log_id,
    role: opts.role,
    revoked_fingerprint: opts.revoked_fingerprint,
    revoked_at_tree_size: opts.revoked_at_tree_size,
    reason: opts.reason || 'unspecified',
    issued_at: (now || (() => new Date().toISOString()))()
  };
}

function buildKeyRevocation(opts, rootPrivPem, now) {
  const body = buildKeyRevocationBody(opts, now);
  const sig = crypto.sign(null, Buffer.from(core.canonicalize(body), 'utf8'),
    crypto.createPrivateKey(rootPrivPem)).toString('base64');
  return { ...body, signature: sig };
}

function buildQuorumKeyRevocation(opts, signerPrivPems, now) {
  const body = buildKeyRevocationBody(opts, now);
  return assembleQuorum(body, (signerPrivPems || []).map(p => signQuorumPart(body, p)));
}

// Revokacio ellenorzese a root-horgonnyal (PEM vagy trust-root objektum) -
// szerkezetileg a verifyKeySuccession tukre. -> { ok, problems }
function verifyKeyRevocation(rev, rootAnchor) {
  const problems = [];
  if (!rev || typeof rev !== 'object') return { ok: false, problems: ['nem objektum'] };
  if (rev.record_type !== 'key_revocation') problems.push('record_type != key_revocation');
  if (!ROLES.includes(rev.role)) problems.push('ervenytelen role');
  if (!rev.revoked_fingerprint) problems.push('hianyzo revoked_fingerprint');
  if (!Number.isInteger(rev.revoked_at_tree_size) || rev.revoked_at_tree_size < 1)
    problems.push('ervenytelen revoked_at_tree_size');
  if (problems.length) return { ok: false, problems };

  let mode = null;
  if (typeof rootAnchor === 'string') mode = { mode: 'single', keys: [rootAnchor], threshold: 1 };
  else if (rootAnchor && rootAnchor.record_type === 'trust_root') {
    mode = trustRootMode(rootAnchor);
    if (mode.mode === 'invalid') return { ok: false, problems: problems.concat(mode.problems) };
  } else return { ok: false, problems: problems.concat(['ervenytelen root-horgony (PEM vagy trust-root objektum kell)']) };

  if (mode.mode === 'quorum') {
    const q = verifyQuorumSigned(rev, mode.keys, mode.threshold);
    return { ok: problems.length === 0 && q.ok, problems: problems.concat(q.problems) };
  }
  if (!rev.signature) return { ok: false, problems: problems.concat(['hianyzo signature']) };
  const body = { ...rev }; delete body.signature;
  try {
    const ok = crypto.verify(null, Buffer.from(core.canonicalize(body), 'utf8'),
      crypto.createPublicKey(mode.keys[0]), Buffer.from(rev.signature, 'base64'));
    if (!ok) problems.push('a revokacio alairasa ERVENYTELEN a root-kulcsra');
  } catch (e) { problems.push('revokacio alairas-ellenorzes hiba: ' + e.message); }
  return { ok: problems.length === 0, problems };
}

// ═══════════════════════════════════════════════════════════════════════════════
// 0.8 - Witness-kor (STH cosignature-ok, megelozo equivocation-vedelem)
// ═══════════════════════════════════════════════════════════════════════════════
// A 0.3 Monitor IDOBEN/NEZETEK KOZOTT fogja az equivocationt (utolagos). A 0.8
// MEGELOZOVE teszi az ELFOGADASI kapunal: egy STH-t a fogyaszto addig nem fogad
// el teljes bizalommal, amig threshold-nyi FUGGETLEN witness alá nem irta.
//
// Ez csak akkor preventiv, ha a witness STATEFUL (Meridian-invarians): egy
// witness csak append-only folytatast cosignol az altala utoljara latott
// STH-hoz - igy egy operator nem tud threshold-nyi cosignature-t szerezni egy
// split-view agra. Az append-only ellenorzes a WITNESS oldalan tortenik (lasd
// axr-witness CLI); a protokoll a cosignature FORMATUMAT es a fogyasztoi
// threshold-ellenorzest rogziti.
//
// A witness-kor a CONTROL LOGBAN el (root/kvorum-alairt witness_set rekord),
// NEM a trust-rootban - operativ eletciklus, ujrahasznalja a 0.7 csatornat.

const WITNESS_VERSION = '0.8';

function buildWitnessSetBody(opts, now) {
  if (!opts.log_id) throw new Error('witness_set: log_id kotelezo');
  const witnesses = (opts.witnesses || []).map(w =>
    (typeof w === 'string') ? { name: keyFingerprint(w).slice(7, 19), public_key: w }
                            : { name: w.name || keyFingerprint(w.public_key).slice(7, 19), public_key: w.public_key });
  if (!witnesses.length) throw new Error('witness_set: legalabb egy witness kell');
  for (const w of witnesses) if (!w.public_key) throw new Error('witness_set: hianyzo witness public_key');
  if (!Number.isInteger(opts.witness_threshold) || opts.witness_threshold < 1 || opts.witness_threshold > witnesses.length)
    throw new Error('witness_set: witness_threshold 1..' + witnesses.length + ' kell legyen');
  if (!Number.isInteger(opts.effective_from_tree_size) || opts.effective_from_tree_size < 1)
    throw new Error('witness_set: effective_from_tree_size pozitiv egesz kell legyen');
  return {
    axr_version: WITNESS_VERSION,
    record_type: 'witness_set',
    log_id: opts.log_id,
    witnesses,
    witness_threshold: opts.witness_threshold,
    effective_from_tree_size: opts.effective_from_tree_size,
    reason: opts.reason || 'unspecified',
    issued_at: (now || (() => new Date().toISOString()))()
  };
}
function buildWitnessSet(opts, rootPrivPem, now) {
  const body = buildWitnessSetBody(opts, now);
  const sig = crypto.sign(null, Buffer.from(core.canonicalize(body), 'utf8'),
    crypto.createPrivateKey(rootPrivPem)).toString('base64');
  return { ...body, signature: sig };
}
function buildQuorumWitnessSet(opts, signerPrivPems, now) {
  const body = buildWitnessSetBody(opts, now);
  return assembleQuorum(body, (signerPrivPems || []).map(p => signQuorumPart(body, p)));
}

// witness_set ellenorzese a root-horgonnyal (PEM | trust-root | lanc). -> {ok,problems}
function verifyWitnessSet(rec, rootAnchor) {
  const problems = [];
  if (!rec || typeof rec !== 'object') return { ok: false, problems: ['nem objektum'] };
  if (rec.record_type !== 'witness_set') problems.push('record_type != witness_set');
  if (!rec.log_id) problems.push('hianyzo log_id');
  if (!Array.isArray(rec.witnesses) || !rec.witnesses.length) problems.push('ures/hianyzo witnesses');
  const n = Array.isArray(rec.witnesses) ? rec.witnesses.length : 0;
  if (!Number.isInteger(rec.witness_threshold) || rec.witness_threshold < 1 || rec.witness_threshold > n)
    problems.push('ervenytelen witness_threshold');
  if (!Number.isInteger(rec.effective_from_tree_size) || rec.effective_from_tree_size < 1)
    problems.push('ervenytelen effective_from_tree_size');
  if (problems.length) return { ok: false, problems };

  let mode = null;
  if (typeof rootAnchor === 'string') mode = { mode: 'single', keys: [rootAnchor], threshold: 1 };
  else if (rootAnchor && rootAnchor.record_type === 'trust_root') {
    mode = trustRootMode(rootAnchor);
    if (mode.mode === 'invalid') return { ok: false, problems: mode.problems };
  } else return { ok: false, problems: ['ervenytelen root-horgony'] };

  if (mode.mode === 'quorum') {
    const q = verifyQuorumSigned(rec, mode.keys, mode.threshold);
    return { ok: q.ok, problems: q.problems };
  }
  if (!rec.signature) return { ok: false, problems: ['hianyzo signature'] };
  const body = { ...rec }; delete body.signature;
  try {
    const ok = crypto.verify(null, Buffer.from(core.canonicalize(body), 'utf8'),
      crypto.createPublicKey(mode.keys[0]), Buffer.from(rec.signature, 'base64'));
    if (!ok) problems.push('a witness_set alairasa ERVENYTELEN a root-kulcsra');
  } catch (e) { problems.push('witness_set alairas-ellenorzes hiba: ' + e.message); }
  return { ok: problems.length === 0, problems };
}

// Witness-idovonal a (root-verifikalt) witness_set rekordokbol. A witness_set
// rekordok ABSZOLUT policy-deklaraciok (nincs predecessor-lancolas, mint a
// successionnel): minden root-autorizalt. Az adott tree_size-nal a legkesobbi
// effective_from <= tree_size az aktiv. Azonos effective_from-ra ket eltero
// keszlet = ambiguitas -> fail-closed (a hatar konfliktusos, nem valasztunk).
//   -> { timeline: [{ from_tree_size, witnesses:[{name,fingerprint,pem}], threshold }], problems }
function buildWitnessTimeline(witnessSets, rootAnchor) {
  const problems = [];
  const valid = [];
  const seen = new Set();
  for (const w of (witnessSets || [])) {
    if (!w || w.record_type !== 'witness_set') continue;
    const h = core.sha256(w); if (seen.has(h)) continue; seen.add(h);
    const v = verifyWitnessSet(w, rootAnchor);
    if (!v.ok) { problems.push('elvetett witness_set (effective_from=' + (w && w.effective_from_tree_size) + '): ' + v.problems.join('; ')); continue; }
    valid.push(w);
  }
  valid.sort((a, b) => a.effective_from_tree_size - b.effective_from_tree_size);
  const timeline = [];
  for (let i = 0; i < valid.length; i++) {
    const w = valid[i];
    const next = valid[i + 1];
    if (next && next.effective_from_tree_size === w.effective_from_tree_size) {
      // ket eltero witness_set ugyanarra a hatarra (a dedup mar kiszurte az
      // azonosakat) -> ambiguitas, fail-closed: egyiket sem vesszuk fel
      problems.push('witness_set utkozes effective_from=' + w.effective_from_tree_size + ' - ambiguous policy, kihagyva');
      // ugorjuk at az osszes azonos hatarut
      let j = i;
      while (valid[j + 1] && valid[j + 1].effective_from_tree_size === w.effective_from_tree_size) j++;
      i = j;
      continue;
    }
    timeline.push({
      from_tree_size: w.effective_from_tree_size,
      threshold: w.witness_threshold,
      witnesses: w.witnesses.map(x => ({ name: x.name, pem: x.public_key, fingerprint: keyFingerprint(x.public_key) }))
    });
  }
  return { timeline, problems };
}

function witnessAt(timeline, treeSize) {
  let chosen = null;
  for (const e of timeline) { if (e.from_tree_size <= treeSize) chosen = e; else break; }
  return chosen;
}

// Egy witness cosignolasa egy STH felett. Az uzenet a kanonikus STH a
// witness_cosignatures mezo NELKUL (de az operator-alairasaval EGYUTT - igy a
// cosignature a konkret operator-alairt STH-hoz kotodik).
function cosignWitness(sth, witnessPrivPem) {
  const body = { ...sth }; delete body.witness_cosignatures;
  const priv = crypto.createPrivateKey(witnessPrivPem);
  const pubPem = crypto.createPublicKey(priv).export({ type: 'spki', format: 'pem' });
  return {
    witness_fingerprint: keyFingerprint(pubPem),
    signature: crypto.sign(null, Buffer.from(core.canonicalize(body), 'utf8'), priv).toString('base64')
  };
}
// Cosignature-ok hozzaadasa az STH-hoz (determinisztikus: fingerprint szerint).
function assembleWitnessCosignatures(sth, parts) {
  const sorted = (parts || []).slice().sort((a, b) =>
    a.witness_fingerprint < b.witness_fingerprint ? -1 : a.witness_fingerprint > b.witness_fingerprint ? 1 : 0);
  return { ...sth, witness_cosignatures: sorted };
}

// Egy STH witness-cosignature-einek ellenorzese az adott (aktiv) witness-keszlet
// ellen. SZIGORU fail-closed az ANOMALIAKRA (nem-deklaralt/duplikalt/rendezetlen/
// ervenytelen alairas); a threshold ALATTISAG NEM anomalia, hanem kulon jelzes
// (UNDER_WITNESSED a fogyasztoknal). -> { validCount, threshold, anomalies: [] }
function verifyWitnessCosignatures(sth, witnessEntry) {
  const anomalies = [];
  const threshold = witnessEntry ? witnessEntry.threshold : 0;
  const cosigs = Array.isArray(sth.witness_cosignatures) ? sth.witness_cosignatures : [];
  if (!witnessEntry) return { validCount: 0, threshold: 0, anomalies };
  const byFp = new Map();
  for (const w of witnessEntry.witnesses) byFp.set(w.fingerprint, w.pem);
  const body = { ...sth }; delete body.witness_cosignatures;
  const msg = Buffer.from(core.canonicalize(body), 'utf8');
  let valid = 0, prevFp = null;
  for (const part of cosigs) {
    if (!part || !part.witness_fingerprint || !part.signature) { anomalies.push('hianyos cosignature-bejegyzes'); continue; }
    if (prevFp !== null && !(part.witness_fingerprint > prevFp))
      anomalies.push('nem-determinisztikus cosignature-sorrend: ' + part.witness_fingerprint.slice(0, 20) + '...');
    prevFp = part.witness_fingerprint;
    const pem = byFp.get(part.witness_fingerprint);
    if (!pem) { anomalies.push('nem-deklaralt witness: ' + part.witness_fingerprint.slice(0, 20) + '...'); continue; }
    try {
      if (crypto.verify(null, msg, crypto.createPublicKey(pem), Buffer.from(part.signature, 'base64'))) valid++;
      else anomalies.push('ERVENYTELEN cosignature: ' + part.witness_fingerprint.slice(0, 20) + '...');
    } catch (e) { anomalies.push('cosignature-ellenorzes hiba: ' + e.message); }
  }
  return { validCount: valid, threshold, anomalies };
}

// ── Kulcs-idovonal epitese genesisbol + successionokbol ───────────────────────
// A megadott role-ra epit egy idovonalat. Minden succession a root-kulccsal
// verifikalt; a lanc a genesis fingerprintjebol indul es predecessor-linkelt.
// Hezag/tort lanc/sorrendi hiba -> az adott szegmens authorized=false.
//
//   genesisPem   : a role genesis-kulcsa (trust-rootbol). Ha null -> degradalt mod.
//   successions  : key_succession rekordok (vegyes role megengedett, szurunk).
//   role         : 'sth' | 'receipt'
//   rootAnchor   : a pinned root-kulcs PEM (0.5) VAGY trust-root objektum (0.6,
//                  kvorum-modot is tamogat) - a successionok ezzel verifikalnak.
//   revocations  : (opc., 0.6) key_revocation rekordok. A root-verifikalt,
//                  role-egyezo revokaciok a talalt szegmensekre revoked_from
//                  mezot tesznek: a kulcs a revoked_from-tol mar NEM irhat ala
//                  (a fogyasztok KEY_REVOKED-kent jelentik). A revokacio a
//                  szegmens authorized statuszat nem irja at - a mar tanusitott
//                  mult ervenyessege a fogyasztok bizonyitek-szabalyan mulik.
//
// -> { timeline: [ { from_tree_size, pem, fingerprint, authorized } ], problems }
//    A timeline from_tree_size szerint novekvo; az elso elem a genesis (from=0).
function buildKeyTimeline(genesisPem, successions, role, rootAnchor, revocations) {
  const problems = [];
  if (!genesisPem) {
    // Degradalt mod: nincs root-horgonyzott genesis. Ures idovonal -> a hivo
    // (monitor) fail-closed modra esik vissza.
    return { timeline: [], problems: ['nincs genesis-kulcs ehhez a role-hoz/log_id-hoz (degradalt mod)'] };
  }
  // 1. csak ehhez a role-hoz tartozo, root-kulccsal ERVENYES successionok
  const valid = [];
  for (const s of (successions || [])) {
    if (!s || s.record_type !== 'key_succession' || s.role !== role) continue;
    const v = verifyKeySuccession(s, rootAnchor);
    if (!v.ok) { problems.push('elvetett succession (effective_from=' + (s && s.effective_from_tree_size) + '): ' + v.problems.join('; ')); continue; }
    valid.push(s);
  }
  // 2. rendezes effective_from szerint; egyenlo effective_from = utkozes
  valid.sort((a, b) => a.effective_from_tree_size - b.effective_from_tree_size);
  const timeline = [{ from_tree_size: 0, pem: genesisPem, fingerprint: keyFingerprint(genesisPem), authorized: true }];
  let activeFp = timeline[0].fingerprint;
  let chainOk = true;  // TRANZITIV autorizacio: az eddigi lanc MINDEN szeme ep-e
  let lastFrom = 0;
  // Csoportositas effective_from szerint: TOBB rekord ugyanarra a hatarra = FORK.
  // (A rendezes utan az azonos hatarok szomszedosak.)
  const groups = [];
  for (const s of valid) {
    const g = groups[groups.length - 1];
    if (g && g[0].effective_from_tree_size === s.effective_from_tree_size) g.push(s);
    else groups.push([s]);
  }
  for (const g of groups) {
    const ef = g[0].effective_from_tree_size;
    if (g.length > 1) {
      // FORK: ket (vagy tobb) root-alairt, konkurens succession ugyanarra a
      // hatarra ket lehetseges utodkulcsot jelentene ugyanarra a tree_size-ra.
      // Fail-closed (Meridian-review talalata): NEM "first-wins" - EGYIK ag sem
      // autorizalt, es a lanc innentol vegleg mergezett (activeFp=null), igy a
      // barmelyik agra epitett tovabbi rotacio is unauthorized marad. Kulonben
      // eltero input-sorrendu / reszleges lathatosagu monitorok mas-mas aktiv
      // kulcsot fogadnanak el ugyanarra a tree_size-ra (causality-fork).
      problems.push('utkozes (FORK): ' + g.length + ' konkurens succession ugyanarra a hatarra ' +
        'effective_from=' + ef + ' - egyik sem autorizalt, a lanc innentol fail-closed');
      for (const s of g)
        timeline.push({ from_tree_size: ef, pem: s.successor_public_key,
          fingerprint: s.successor_fingerprint, authorized: false });
      activeFp = null;
      chainOk = false;
      lastFrom = ef;
      continue;
    }
    const s = g[0];
    // lanc-folytonossag: a predecessor az aktualis aktiv kulcs? (fork utan
    // activeFp=null -> semmi nem linkelhet ervenyesen)
    const linkOk = activeFp !== null && s.predecessor_fingerprint === activeFp;
    if (!linkOk && activeFp !== null)
      problems.push('tort lanc effective_from=' + ef +
        ': predecessor ' + s.predecessor_fingerprint.slice(0, 20) + '... != aktiv ' + activeFp.slice(0, 20) + '...');
    // Az autorizacio tranzitiv (fail-closed): tort lancszem UTAN a "szabalyosan"
    // lancolt utodok sem gyogyulnak vissza - kulonben egy tamado egy tort
    // ugrassal beallhatna a lancba, es az arra epitett tovabbi rotacioi mar
    // autorizaltnak latszananak (NEXUS-review talalata). A tores csak egyszer
    // kerul a problems-be; a tovabbi szegmensek csendben authorized=false.
    const authorized = linkOk && chainOk;
    timeline.push({ from_tree_size: ef, pem: s.successor_public_key,
      fingerprint: s.successor_fingerprint, authorized });
    // a lanc tovabbgordul (a kovetkezo szem elod-hivatkozasa igy ellenorizheto),
    // de az autorizalt statusz mar nem allithato helyre ezen az idovonalon
    activeFp = s.successor_fingerprint;
    chainOk = authorized;
    lastFrom = ef;
  }
  // 0.6: revokaciok alkalmazasa - csak a root-verifikalt, role-egyezo rekordok.
  // Ha tobb revokacio eri ugyanazt a kulcsot, a legkorabbi hatar gyoz.
  for (const r of (revocations || [])) {
    if (!r || r.record_type !== 'key_revocation' || r.role !== role) continue;
    const v = verifyKeyRevocation(r, rootAnchor);
    if (!v.ok) { problems.push('elvetett revokacio (revoked_at=' + (r && r.revoked_at_tree_size) + '): ' + v.problems.join('; ')); continue; }
    let hit = false;
    for (const e of timeline) {
      if (e.fingerprint !== r.revoked_fingerprint) continue;
      hit = true;
      if (e.revoked_from == null || r.revoked_at_tree_size < e.revoked_from)
        e.revoked_from = r.revoked_at_tree_size;
    }
    if (!hit) problems.push('revokacio nem-letezo idovonal-kulcsra: ' + r.revoked_fingerprint.slice(0, 20) + '...');
  }
  return { timeline, problems };
}

// Az adott tree_size-nal ervenyes idovonal-bejegyzes (a legnagyobb from <= treeSize).
function keyAtTreeSize(timeline, treeSize) {
  let chosen = null;
  for (const e of timeline) {
    if (e.from_tree_size <= treeSize) chosen = e; else break;
  }
  return chosen;
}

module.exports = {
  SUCCESSION_VERSION,
  ROLES,
  keyFingerprint,
  buildTrustRoot,
  buildTrustRootBody,
  buildQuorumTrustRoot,
  buildTrustRootSuccessor,
  verifyTrustRoot,
  verifyTrustRootChain,
  parseTrustRootInput,
  trustRootMode,
  signQuorumPart,
  assembleQuorum,
  verifyQuorumSigned,
  genesisKey,
  buildKeySuccession,
  buildKeySuccessionBody,
  buildQuorumKeySuccession,
  verifyKeySuccession,
  REVOCATION_VERSION,
  buildKeyRevocation,
  buildKeyRevocationBody,
  buildQuorumKeyRevocation,
  verifyKeyRevocation,
  buildKeyTimeline,
  keyAtTreeSize,
  WITNESS_VERSION,
  buildWitnessSet,
  buildWitnessSetBody,
  buildQuorumWitnessSet,
  verifyWitnessSet,
  buildWitnessTimeline,
  witnessAt,
  cosignWitness,
  assembleWitnessCosignatures,
  verifyWitnessCosignatures
};
