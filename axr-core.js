// ═══════════════════════════════════════════════════════════════════════════════
// AXR - Agent Execution Receipt - Core Library v0.2
// ═══════════════════════════════════════════════════════════════════════════════
// Ez a fuggvenykonyvtar mindket helyen hasznalhato:
//  - az N8N Code node-ban (receipt generalas)
//  - egy kulonallo verifikalo szkriptben (receipt ellenorzes)
// Nulla kulso fuggoseg - csak a Node beepitett crypto modulja.
//
// 0.2 valtozas: az input_hash mostantol minden lepesnel a lepes TENYLEGES
// inputjabol szamol, nem a kozos normalizalt payload-bol (spec 7.1). Ehhez
// minden tanusitando node a kimenetebe tesz egy __axr_input markert. A core
// itt csak a marker-konvencio kozos helpereit adja; a kiolvasas/eltavolitas
// logikaja egy helyen el, hogy a generator es a verifier ne terjen el.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');

// ── Protokoll-verzio ───────────────────────────────────────────────────────────
// Minden ujonnan generalt receipt ezt a verziot kapja. A verifier a receipt
// sajat axr_version mezoje szerint agazik el, igy a regi 0.1 lancok tovabbra is
// ervenyesek maradnak (spec: visszafele kompatibilis verifikalas).
const AXR_VERSION = '0.2';

// A marker mezo neve, amit minden tanusitando node a kimenetebe tesz.
// Alahuzas-prefix: jelzi hogy ez AXR-meta, nem uzleti adat.
const AXR_INPUT_KEY = '__axr_input';

// 0.3: a generativ (LLM) lepes ezt a markert csatolja a kimenetehez. A
// tartalma a modell-hivas evidenciaja: model, parameterek, prompt/tool/
// completion hash (vagy nyers tartalom), usage, finish_reason, reproducibility.
// A generator innen tolti a receipt 'generation' blokkjat (spec 5.3).
const AXR_GEN_KEY = '__axr_gen';

// ── Determinisztikus JSON szerializalas ────────────────────────────────────────
// A hash es az alairas CSAK akkor reprodukalhato, ha a kulcsok sorrendje fix.
// JSON.stringify nem garantalja ezt mely objektumoknal, ezert sajat szerializalo.
function canonicalize(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalize).join(',') + ']';
  }
  const keys = Object.keys(value).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}';
}

// ── SHA-256 hash egy tetszoleges ertekrol ──────────────────────────────────────
function sha256(value) {
  const input = typeof value === 'string' ? value : canonicalize(value);
  return 'sha256:' + crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

// ── Verzio-osszehasonlitas ──────────────────────────────────────────────────────
// "0.3" >= "0.2" -> true. Egyszeru major.minor parse, elegendo amig a verzio
// "X.Y" formatumu. Kozos a verifierrel, hogy a ket oldal ne terjen el.
function versionAtLeast(v, min) {
  if (!v) return false;
  const pa = String(v).split('.').map(Number);
  const pb = String(min).split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const a = pa[i] || 0, b = pb[i] || 0;
    if (a > b) return true;
    if (a < b) return false;
  }
  return true;
}

// ── Alairhato resz - verzio-fuggo mezo-kihagyas (0.3) ───────────────────────────
// 0.1/0.2: az alairas a receiptet a 'signature' mezo NELKUL fedi.
// 0.3:     a 'signature' ES az 'anchor_ref' is kimarad. Az anchor_ref az alairas
//          UTAN irodik a receiptbe (a horgonyzas keson, kotegelve tortenik), ezert
//          nem szabad, hogy visszamenoleg ervenytelenitse az alairast (spec 4.1).
//          0.1/0.2 receiptnel nincs anchor_ref, igy a torles no-op - visszafele
//          kompatibilis.
function signablePart(receipt) {
  const clone = { ...receipt };
  delete clone.signature;
  if (versionAtLeast(receipt.axr_version, '0.3')) {
    delete clone.anchor_ref;
  }
  return clone;
}

// ── Lanc-hash (previous_receipt_hash / chain_root_hash / previous_sth_hash) ─────
// A lancolasi hash a receiptet az anchor_ref NELKUL fedi - akkor is, ha az
// anchor_ref jelen van null-kent. Igy a hash stabil marad, amikor a horgonyzas
// kesobb kitolti az anchor_ref-et. Egy helyen el, hogy a generator (lancolaskor)
// es a verifier garantaltan ugyanazt szamolja. 0.1/0.2-nel nincs anchor_ref kulcs,
// ezert ez no-op - visszafele kompatibilis.
function chainHash(receipt) {
  if (receipt && typeof receipt === 'object' && 'anchor_ref' in receipt) {
    const clone = { ...receipt };
    delete clone.anchor_ref;
    return sha256(clone);
  }
  return sha256(receipt);
}

// ── Ed25519 alairas ────────────────────────────────────────────────────────────
// A receiptet kanonikus formaban, a verziohoz tartozo mezo-kihagyassal irjuk ala.
function signReceipt(receipt, privateKeyPem) {
  const privateKey = crypto.createPrivateKey(privateKeyPem);
  const message = Buffer.from(canonicalize(signablePart(receipt)), 'utf8');
  const signature = crypto.sign(null, message, privateKey);
  return signature.toString('base64');
}

// ── Ed25519 alairas ellenorzes ─────────────────────────────────────────────────
function verifyReceipt(receipt, publicKeyPem) {
  const publicKey = crypto.createPublicKey(publicKeyPem);
  if (!receipt.signature) return false;
  const message = Buffer.from(canonicalize(signablePart(receipt)), 'utf8');
  return crypto.verify(null, message, publicKey, Buffer.from(receipt.signature, 'base64'));
}

// ── UUID v4 ────────────────────────────────────────────────────────────────────
function uuid() {
  return crypto.randomUUID();
}

// ── PII customer reference - nev+email+telefon egyiranyu hash ──────────────────
function customerRef(name, email, phone) {
  return sha256([name || '', email || '', phone || ''].join('|').toLowerCase());
}

// ── __axr_input marker kezelese ────────────────────────────────────────────────
// Minden tanusitando node a kimenetebe tesz egy __axr_input mezot, ami a node
// TENYLEGES bemenete. A generator innen szamolja az input_hash-t. Ez teszi a
// generatort workflow-agnosztikussa: nem kell tudnia a graph szerkezetet (ez
// egyben a 7.2 $('NodeName')-toredekenyseg lezarasa is).
//
// splitAxrInput(nodeOutput) -> { input, output }
//   input  : a node tenyleges bemenete (a marker erteke), vagy undefined ha
//            a node nem hagyott markert (pl. regi node, vagy hibas konfiguracio)
//   output : a node kimenete a marker NELKUL - ezt kell output_hash-elni, hogy
//            a marker jelenlete ne valtoztassa meg az output_hash-t
//
// Ez a fuggveny EGY helyen el, hogy a generator es a verifier garantaltan
// ugyanazt csinalja.
function splitAxrInput(nodeOutput) {
  // tomb-kimenet (n8n itemek): az elso item hordozza a markert
  if (Array.isArray(nodeOutput)) {
    if (nodeOutput.length === 0) return { input: undefined, output: nodeOutput };
    const first = nodeOutput[0];
    const restItems = nodeOutput.slice(1);
    if (first && typeof first === 'object' && !Array.isArray(first) && AXR_INPUT_KEY in first) {
      const { [AXR_INPUT_KEY]: input, ...cleanFirst } = first;
      return { input, output: [cleanFirst, ...restItems] };
    }
    return { input: undefined, output: nodeOutput };
  }
  // objektum-kimenet
  if (nodeOutput && typeof nodeOutput === 'object' && AXR_INPUT_KEY in nodeOutput) {
    const { [AXR_INPUT_KEY]: input, ...clean } = nodeOutput;
    return { input, output: clean };
  }
  return { input: undefined, output: nodeOutput };
}

// ── __axr_gen marker kezelese (0.3) ────────────────────────────────────────────
// Ugyanaz a minta, mint a splitAxrInput, de a generativ-lepes markerere. Egy
// generativ node MINDKET markert hordozza (__axr_input + __axr_gen); a generator
// eloszor a splitAxrInput-ot hivja, majd ezt a maradek kimeneten, hogy a tiszta
// output_hash egyik markert se tartalmazza.
//
// splitAxrGen(nodeOutput) -> { gen, output }
//   gen    : a generativ capture blokk (model/params/prompt/completion/...), vagy
//            undefined ha a node nem generativ (nincs marker)
//   output : a kimenet a __axr_gen marker NELKUL
function splitAxrGen(nodeOutput) {
  if (Array.isArray(nodeOutput)) {
    if (nodeOutput.length === 0) return { gen: undefined, output: nodeOutput };
    const first = nodeOutput[0];
    const restItems = nodeOutput.slice(1);
    if (first && typeof first === 'object' && !Array.isArray(first) && AXR_GEN_KEY in first) {
      const { [AXR_GEN_KEY]: gen, ...cleanFirst } = first;
      return { gen, output: [cleanFirst, ...restItems] };
    }
    return { gen: undefined, output: nodeOutput };
  }
  if (nodeOutput && typeof nodeOutput === 'object' && AXR_GEN_KEY in nodeOutput) {
    const { [AXR_GEN_KEY]: gen, ...clean } = nodeOutput;
    return { gen, output: clean };
  }
  return { gen: undefined, output: nodeOutput };
}

// ── Generation blokk epitese a markerbol (0.3, spec 5.3) ───────────────────────
// A node a nyers anyagot is csatolhatja (prompt/tools/completion) - ekkor itt
// szamoljuk a hash-eket -, vagy mar elore kiszamolt hash-eket. Egy helyen el,
// hogy a node es barmely ujraszamolo fel ugyanazt a hash-t kapja.
//   gen.prompt / gen.completion : nyers ordered message-lista / valasz -> hasheljuk
//   gen.tools                   : tool-definiciok (vagy null)
//   gen.*_hash                  : ha a node mar elore hashelt, azt hasznaljuk
function buildGeneration(gen) {
  if (!gen || typeof gen !== 'object') return null;
  const h = (v, pre) => (v !== undefined && v !== null) ? sha256(v) : (pre || null);
  return {
    params: gen.params || {},
    prompt_hash: gen.prompt !== undefined ? sha256(gen.prompt) : (gen.prompt_hash || null),
    tools_hash: (gen.tools !== undefined && gen.tools !== null) ? sha256(gen.tools) : (gen.tools_hash || null),
    completion_hash: gen.completion !== undefined ? sha256(gen.completion) : (gen.completion_hash || null),
    prompt_ref: gen.prompt_ref || null,
    completion_ref: gen.completion_ref || null,
    usage: gen.usage || null,
    finish_reason: gen.finish_reason || null,
    reproducibility: gen.reproducibility ||
      { level: 'best_effort', deterministic_settings: false, notes: '' }
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// 0.3 - Merkle-fa es kulso horgonyzas (RFC 6962 / Certificate Transparency)
// ═══════════════════════════════════════════════════════════════════════════════
// A 0.3 a receipt-hasheket egy RFC 6962 stilusu Merkle-faba kotegeli. A fa
// gyokeret idoszakosan alairjuk (Signed Tree Head) es egy fuggetlen, append-only
// szolgaltatasban (Rekor / RFC 3161 TSA / OpenTimestamps) horgonyozzuk le. Minden
// receipt kap egy inclusion proof-ot, az egymast koveto fa-fejek kozott pedig
// consistency proof bizonyitja, hogy az ujabb fa a regi append-only bovitese.
//
// A hashing PONTOSAN az RFC 6962 szabalyait koveti (domain separation: 0x00 a
// leveleknel, 0x01 a belso csomoknal; a split a legnagyobb 2-hatvany n alatt),
// igy a fa byte-kompatibilis a letezo CT/Rekor verifikalokkal.
// ═══════════════════════════════════════════════════════════════════════════════

const LEAF_PREFIX = Buffer.from([0x00]);
const NODE_PREFIX = Buffer.from([0x01]);

// "sha256:hex" <-> Buffer konverziok. A receiptekben minden hash string-kent el.
function _sha256Bytes(buf) { return crypto.createHash('sha256').update(buf).digest(); }
function _toHashStr(buf) { return 'sha256:' + buf.toString('hex'); }
function _fromHashStr(s) {
  if (Buffer.isBuffer(s)) return s;
  return Buffer.from(String(s).replace(/^sha256:/, ''), 'hex');
}

// ── Level- es csomo-hash (RFC 6962 domain separation) ──────────────────────────
// A level bemenete a TELJES alairt receipt kanonikus bajtjai, az anchor_ref
// NELKUL (az anchor_ref a level kepzese utan irodik - spec 6.2).
function leafInputBytes(receipt) {
  const clone = { ...receipt };
  delete clone.anchor_ref;
  return Buffer.from(canonicalize(clone), 'utf8');
}
function leafHash(receipt) {
  return _toHashStr(_sha256Bytes(Buffer.concat([LEAF_PREFIX, leafInputBytes(receipt)])));
}
function nodeHash(left, right) {
  return _toHashStr(_sha256Bytes(Buffer.concat([NODE_PREFIX, _fromHashStr(left), _fromHashStr(right)])));
}

// A legnagyobb 2-hatvany, ami szigoruan kisebb n-nel (RFC 6962 split pont).
function largestPowerOfTwoLessThan(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

// ── Merkle Tree Hash (RFC 6962) egy level-hash tomb felett ─────────────────────
// Bemenet: level-hash string-ek tombje. n==1 -> a level-hash maga a gyoker.
function _mth(leafHashes) {
  const n = leafHashes.length;
  if (n === 0) return _toHashStr(_sha256Bytes(Buffer.alloc(0)));
  if (n === 1) return leafHashes[0];
  const k = largestPowerOfTwoLessThan(n);
  return nodeHash(_mth(leafHashes.slice(0, k)), _mth(leafHashes.slice(k)));
}

// Gyoker egy receipt-tomb felett (a leveleket maga szamolja).
function merkleRoot(receipts) {
  return _mth(receipts.map(leafHash));
}
// Gyoker mar kiszamolt level-hash-ek felett.
function merkleRootFromLeaves(leafHashes) {
  return _mth(leafHashes.slice());
}

// ── Inclusion proof generalas (RFC 6962 PATH) ──────────────────────────────────
// Visszaadja a testver-hashek listajat a leveltol a gyokerig (string-tomb).
function inclusionProof(index, leafHashes) {
  function rec(i, leaves) {
    const n = leaves.length;
    if (n <= 1) return [];
    const k = largestPowerOfTwoLessThan(n);
    if (i < k) return rec(i, leaves.slice(0, k)).concat([_mth(leaves.slice(k))]);
    return rec(i - k, leaves.slice(k)).concat([_mth(leaves.slice(0, k))]);
  }
  return rec(index, leafHashes.slice());
}

// ── Inclusion proof ellenorzes - gyoker visszaszamolasa (CT iterativ algoritmus)
// Ezt barmely auditor lefuttathatja: level-hash + index + fa-meret + proof -> gyoker.
function rootFromInclusionProof(leafHashStr, index, treeSize, proofStrs) {
  if (index < 0 || index >= treeSize) throw new Error('index a fa hatarain kivul');
  let fn = index, sn = treeSize - 1;
  let r = leafHashStr;
  for (const p of proofStrs) {
    if (sn === 0) throw new Error('inclusion proof tul hosszu');
    if ((fn & 1) === 1 || fn === sn) {
      r = nodeHash(p, r);
      if ((fn & 1) === 0) {
        do { fn >>= 1; sn >>= 1; } while ((fn & 1) === 0 && fn !== 0);
      }
    } else {
      r = nodeHash(r, p);
    }
    fn >>= 1; sn >>= 1;
  }
  if (sn !== 0) throw new Error('inclusion proof tul rovid');
  return r;
}
function verifyInclusion(leafHashStr, index, treeSize, proofStrs, expectedRootStr) {
  try {
    return rootFromInclusionProof(leafHashStr, index, treeSize, proofStrs) === expectedRootStr;
  } catch (e) { return false; }
}

// ── Consistency proof generalas (RFC 6962 SUBPROOF) ────────────────────────────
// Bizonyitja, hogy az elso m level egy korabbi fa, amit az n-meretu fa
// append-only modon bovit. Bemenet: level-hash tomb (n elem) + m.
function consistencyProof(m, leafHashes) {
  const n = leafHashes.length;
  if (m <= 0 || m > n) throw new Error('ervenytelen m a consistency proof-hoz');
  if (m === n) return [];
  function sub(mm, leaves, onPath) {
    const nn = leaves.length;
    if (mm === nn) return onPath ? [] : [_mth(leaves)];
    const k = largestPowerOfTwoLessThan(nn);
    if (mm <= k) return sub(mm, leaves.slice(0, k), onPath).concat([_mth(leaves.slice(k))]);
    return sub(mm - k, leaves.slice(k), false).concat([_mth(leaves.slice(0, k))]);
  }
  return sub(m, leafHashes.slice(), true);
}

// ── Consistency proof ellenorzes (CT iterativ algoritmus) ──────────────────────
// Igaz, ha a regi (m-meretu, oldRoot) fa az uj (n-meretu, newRoot) fa prefixe.
function verifyConsistency(m, n, oldRootStr, newRootStr, proofStrs) {
  if (m < 0 || n < m) return false;
  if (m === n) return proofStrs.length === 0 && oldRootStr === newRootStr;
  if (m === 0) return proofStrs.length === 0;

  let node = m - 1, lastNode = n - 1;
  while (node & 1) { node >>= 1; lastNode >>= 1; }

  let p = 0, oldHash, newHash;
  if (node) {
    if (p >= proofStrs.length) return false;
    oldHash = newHash = proofStrs[p++];
  } else {
    oldHash = newHash = oldRootStr;
  }
  while (node) {
    if (node & 1) {
      if (p >= proofStrs.length) return false;
      const h = proofStrs[p++];
      oldHash = nodeHash(h, oldHash);
      newHash = nodeHash(h, newHash);
    } else if (node < lastNode) {
      if (p >= proofStrs.length) return false;
      newHash = nodeHash(newHash, proofStrs[p++]);
    }
    node >>= 1; lastNode >>= 1;
  }
  while (lastNode) {
    if (p >= proofStrs.length) return false;
    newHash = nodeHash(newHash, proofStrs[p++]);
    lastNode >>= 1;
  }
  return p === proofStrs.length && oldHash === oldRootStr && newHash === newRootStr;
}

module.exports = {
  AXR_VERSION,
  AXR_INPUT_KEY,
  AXR_GEN_KEY,
  canonicalize,
  sha256,
  versionAtLeast,
  signablePart,
  chainHash,
  signReceipt,
  verifyReceipt,
  uuid,
  customerRef,
  splitAxrInput,
  splitAxrGen,
  buildGeneration,
  // 0.3 Merkle / anchoring
  leafHash,
  nodeHash,
  largestPowerOfTwoLessThan,
  merkleRoot,
  merkleRootFromLeaves,
  inclusionProof,
  rootFromInclusionProof,
  verifyInclusion,
  consistencyProof,
  verifyConsistency
};
