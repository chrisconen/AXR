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

// ── Genesis-tartalmu trust-root epitese (0.5) ─────────────────────────────────
// A 0.4 trust-root provider-kulcsokat deklaral; a 0.5 ezt kiegesziti a logok
// genesis operator-kulcsaival. Egyetlen root-kulcs alairja mindkettot.
//   providers: [ { provider, public_keys:[pem] } ]            (0.4-bol valtozatlan)
//   logs:      [ { log_id, genesis: { sth: pem, receipt: pem } } ]   (0.5 uj)
function buildTrustRoot(opts, rootPrivPem, rootPubPem, now) {
  const body = {
    axr_version: SUCCESSION_VERSION,
    record_type: 'trust_root',
    issued_at: (now || (() => new Date().toISOString()))(),
    root_public_key: rootPubPem,
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
  const sig = crypto.sign(null, Buffer.from(core.canonicalize(body), 'utf8'),
    crypto.createPrivateKey(rootPrivPem)).toString('base64');
  return { ...body, signature: sig };
}

// A trust-root integritas-ellenorzese (a sajat root_public_key-evel verifikal-e).
// -> { ok, problems }
function verifyTrustRoot(trustRoot) {
  const problems = [];
  if (!trustRoot || typeof trustRoot !== 'object') return { ok: false, problems: ['nem objektum'] };
  if (trustRoot.record_type !== 'trust_root') problems.push('record_type != trust_root');
  if (!trustRoot.root_public_key) problems.push('hianyzo root_public_key');
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
function buildKeySuccession(opts, rootPrivPem, now) {
  if (!ROLES.includes(opts.role)) throw new Error('ervenytelen role: ' + opts.role);
  if (!opts.predecessor_fingerprint) throw new Error('predecessor_fingerprint kotelezo (genesis a trust-rootbol jon)');
  if (!opts.successor_public_key) throw new Error('successor_public_key kotelezo');
  if (!Number.isInteger(opts.effective_from_tree_size) || opts.effective_from_tree_size < 1)
    throw new Error('effective_from_tree_size pozitiv egesz kell legyen');
  const body = {
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
  const sig = crypto.sign(null, Buffer.from(core.canonicalize(body), 'utf8'),
    crypto.createPrivateKey(rootPrivPem)).toString('base64');
  return { ...body, signature: sig };
}

// ── Succession-rekord ellenorzese a ROOT-kulccsal ─────────────────────────────
// -> { ok, problems }. Strukturalis + alairas + fingerprint-konzisztencia.
function verifyKeySuccession(succ, rootPubPem) {
  const problems = [];
  if (!succ || typeof succ !== 'object') return { ok: false, problems: ['nem objektum'] };
  if (succ.record_type !== 'key_succession') problems.push('record_type != key_succession');
  if (!ROLES.includes(succ.role)) problems.push('ervenytelen role');
  if (!succ.predecessor_fingerprint) problems.push('hianyzo predecessor_fingerprint');
  if (!succ.successor_public_key) problems.push('hianyzo successor_public_key');
  if (!Number.isInteger(succ.effective_from_tree_size) || succ.effective_from_tree_size < 1)
    problems.push('ervenytelen effective_from_tree_size');
  if (!succ.signature) problems.push('hianyzo signature');
  if (problems.length) return { ok: false, problems };
  // a deklaralt successor_fingerprint tenyleg a megadott kulcse?
  if (succ.successor_fingerprint !== keyFingerprint(succ.successor_public_key))
    problems.push('successor_fingerprint nem egyezik a successor_public_key-vel');
  const body = { ...succ }; delete body.signature;
  try {
    const ok = crypto.verify(null, Buffer.from(core.canonicalize(body), 'utf8'),
      crypto.createPublicKey(rootPubPem), Buffer.from(succ.signature, 'base64'));
    if (!ok) problems.push('a succession alairasa ERVENYTELEN a root-kulcsra');
  } catch (e) { problems.push('succession alairas-ellenorzes hiba: ' + e.message); }
  return { ok: problems.length === 0, problems };
}

// ── Kulcs-idovonal epitese genesisbol + successionokbol ───────────────────────
// A megadott role-ra epit egy idovonalat. Minden succession a root-kulccsal
// verifikalt; a lanc a genesis fingerprintjebol indul es predecessor-linkelt.
// Hezag/tort lanc/sorrendi hiba -> az adott szegmens authorized=false.
//
//   genesisPem   : a role genesis-kulcsa (trust-rootbol). Ha null -> degradalt mod.
//   successions  : key_succession rekordok (vegyes role megengedett, szurunk).
//   role         : 'sth' | 'receipt'
//   rootPubPem   : a pinned root-kulcs (a successionok ezzel verifikalnak).
//
// -> { timeline: [ { from_tree_size, pem, fingerprint, authorized } ], problems }
//    A timeline from_tree_size szerint novekvo; az elso elem a genesis (from=0).
function buildKeyTimeline(genesisPem, successions, role, rootPubPem) {
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
    const v = verifyKeySuccession(s, rootPubPem);
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
  verifyTrustRoot,
  genesisKey,
  buildKeySuccession,
  verifyKeySuccession,
  buildKeyTimeline,
  keyAtTreeSize
};
