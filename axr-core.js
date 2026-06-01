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

// ── Ed25519 alairas ────────────────────────────────────────────────────────────
// A receipt objektumot a 'signature' mezo NELKUL irjuk ala, kanonikus formaban.
function signReceipt(receiptWithoutSignature, privateKeyPem) {
  const privateKey = crypto.createPrivateKey(privateKeyPem);
  const message = Buffer.from(canonicalize(receiptWithoutSignature), 'utf8');
  const signature = crypto.sign(null, message, privateKey);
  return signature.toString('base64');
}

// ── Ed25519 alairas ellenorzes ─────────────────────────────────────────────────
function verifyReceipt(receipt, publicKeyPem) {
  const publicKey = crypto.createPublicKey(publicKeyPem);
  const { signature, ...rest } = receipt;
  const message = Buffer.from(canonicalize(rest), 'utf8');
  return crypto.verify(null, message, publicKey, Buffer.from(signature, 'base64'));
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

module.exports = {
  AXR_VERSION,
  AXR_INPUT_KEY,
  canonicalize,
  sha256,
  signReceipt,
  verifyReceipt,
  uuid,
  customerRef,
  splitAxrInput
};
