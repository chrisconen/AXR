// ═══════════════════════════════════════════════════════════════════════════════
// AXR Receipt Generator - N8N Code Node v0.2.3 (hardened)
// ═══════════════════════════════════════════════════════════════════════════════
// DROP-IN CSERE a meglevo "AXR Receipt Generator" node jsCode tartalmara.
// A wire format valtozatlanul 0.2 - a meglevo receipts-hu.jsonl lanc
// megszakitas nelkul folytatodik, a regi receiptek tovabbra is verifikalnak.
//
// VALTOZASOK:
//
//  [P0, v0.2.3 - 2026-06-11] N8N SANDBOX KOMPATIBILITAS - typeof-guard a
//       process elerese kore. Az n8n Code node sandboxban nincs process
//       global; a guard nelkuli hivatkozas top-level ReferenceError volt,
//       ami az ELES FOGLALAST torte el ("process is not defined").
//
//  [P0, v0.2.2 - 2026-06-11] LANCOLAS HORGONYZOTT LOG FOLOTT - a
//       readPrevWorkflowHash chainHash-szemantikaval hash-el (anchor_ref es
//       redactable levagva). Enelkul az elso sidecar-horgonyzas utani foglalas
//       torott lancszemet irt volna a logba. Sandbox-reprodukcioval igazolva.
//
//  A v0.2-hoz kepest (2026-06-10, audit utan):
//
//  [P0] GUARDED CANONICALIZER - az axr-core.js 0.2+ guardjai portolva:
//       NaN/Infinity/undefined EXPLICIT hibat dob, nem szerializalodik nemán
//       "null"-la / kimarado mezove. Igy az alairas sosem fed eltero
//       jelentest, es a JS<->Python cross-impl paritas elesben sem torhet el.
//
//  [P0] HMAC-os customer_ref - a sima sha256(name|email|phone) szotar-
//       tamadassal visszafejtheto volt (aki ismer egy email-cimet, meg tudta
//       erositeni, hogy az illeto foglalt-e). Mostantol HMAC-SHA256 egy titkos
//       pepperrel; a pepper elso futaskor generalodik a kulcs melle (mode 600).
//       FIGYELEM: az uj customer_ref ertekek nem linkelhetok a regiekkel -
//       ez szandekos (a regi ertekek gyengek voltak).
//
//  [P1] FAIL-OPEN - a teljes AXR logika try/catch-ben fut. Ha barmi elbukik
//       (hianyzo kulcs, betelt lemez), a FOGLALAS valaszol tovabb, a hiba
//       pedig hangosan megjelenik a __axr.error mezoben, amit a Route by
//       Status utani admin-email is tovabbvisz. A receipt-lyuk igy lathato
//       marad (lanc-hossz-mint-tanusag), de ugyfel-foglalast sosem tor el.
//
//  [AUDIT] logic_version FRISSITVE a tenyleges kodhoz (Normalize 3.3 HU,
//       Brain 5.1 HU, Slot Still Free 2.0 HU) + uj logic_hash mezo: a node
//       jsCode SHA-256 ujjlenyomata. A receipt igy nem csak egy kezzel irt
//       cimket, hanem a kod tenyleges ujjlenyomatat tanusitja. A konstansokat
//       az axr-workflow-lint.js tartja szinkronban (CI gate: exit 1 driftnel).
//
//  [OPS] AXR_DIR felulirhato env-bol (AXR_DIR) - tesztelhetoseg, dev/prod
//       elvalasztas.
//
// Olvassa: Normalize Payload - HU, AXR Mark: Check Day Schedule,
//          The Brain (Logic), AXR Mark: Fresh Calendar Check,
//          Slot Still Free?, AXR Mark: Create Booking
// Ir:  $AXR_DIR/receipts-hu.jsonl  (append-only)
// Alair: $AXR_DIR/signing-key.pem  (ed25519)
// Pepper: $AXR_DIR/customer-pepper.key (32 byte hex, elso futaskor generalodik)
// Fuggoseg: csak beepitett modulok (crypto, fs).
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const fs = require('fs');

const AXR_VERSION = '0.2';
const AXR_INPUT_KEY = '__axr_input';

// v0.2.3: az n8n a Code node-ot sandboxolja - a 'process' global ott NEM
// letezik. A typeof-guard nelkuli process-hivatkozas top-level ReferenceError,
// ami a fail-open try/catch ELOTT robban -> a teljes foglalas elbukik.
// (A tesztek sima Node-ban futottak, ahol van process - ezert nem bukott ki.)
const AXR_DIR = (typeof process !== 'undefined' && process.env && process.env.AXR_DIR)
  || '/home/node/.n8n/axr';
const LOG_PATH = AXR_DIR + '/receipts-hu.jsonl';
const KEY_PATH = AXR_DIR + '/signing-key.pem';
const PEPPER_PATH = AXR_DIR + '/customer-pepper.key';

// ── Kanonikus szerializalas - GUARDED (axr-core 0.2+ szerint) ──────────────────
// NaN/Infinity/undefined: a JSON.stringify ezeket nemán "null"-la alakitja vagy
// kihagyja - kulonbozo szemantika azonos bajtokra kepezve. EXPLICIT eldobjuk.
function canonicalize(value) {
  if (value === undefined) {
    throw new Error('AXR canonicalize: undefined ertek nem szerializalhato');
  }
  if (typeof value === 'number' && !Number.isFinite(value)) {
    throw new Error('AXR canonicalize: NaN/Infinity nem szerializalhato');
  }
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map(k => {
    if (value[k] === undefined) {
      throw new Error(`AXR canonicalize: undefined ertek a(z) "${k}" kulcsnal`);
    }
    return JSON.stringify(k) + ':' + canonicalize(value[k]);
  }).join(',') + '}';
}
function sha256(value) {
  const input = typeof value === 'string' ? value : canonicalize(value);
  return 'sha256:' + crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}
function signReceipt(receiptWithoutSignature, privateKeyPem) {
  const privateKey = crypto.createPrivateKey(privateKeyPem);
  const message = Buffer.from(canonicalize(receiptWithoutSignature), 'utf8');
  return crypto.sign(null, message, privateKey).toString('base64');
}

// ── Pepperes (HMAC) ugyfel-referencia ──────────────────────────────────────────
// A pepper nelkuli sha256 szotar-tamadhato volt. A pepper a kulcs mellett el,
// elso futaskor generalodik. Ha a pepper-fajl nem irhato, a customer_ref null
// lesz es warning keletkezik - hamis/gyenge erteket nem irunk.
function loadOrCreatePepper() {
  if (fs.existsSync(PEPPER_PATH)) {
    return fs.readFileSync(PEPPER_PATH, 'utf8').trim();
  }
  const pepper = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(PEPPER_PATH, pepper + '\n', { encoding: 'utf8', mode: 0o600 });
  return pepper;
}
function customerRef(pepper, name, email, phone) {
  if (!pepper) return null;
  const msg = [name || '', email || '', phone || ''].join('|').toLowerCase();
  return 'hmac-sha256:' + crypto.createHmac('sha256', pepper).update(msg, 'utf8').digest('hex');
}

// ── __axr_input marker levalasztasa (valtozatlan a v0.2-hoz kepest) ────────────
function splitAxrInput(nodeOutput) {
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
  if (nodeOutput && typeof nodeOutput === 'object' && AXR_INPUT_KEY in nodeOutput) {
    const { [AXR_INPUT_KEY]: input, ...clean } = nodeOutput;
    return { input, output: clean };
  }
  return { input: undefined, output: nodeOutput };
}

function safeGet(nodeName) {
  try {
    const items = $(nodeName).all();
    if (!items || items.length === 0) return null;
    return items.map(i => i.json);
  } catch (e) {
    return null;
  }
}

// ── Brain dontes kiemelese (valtozatlan) ───────────────────────────────────────
function extractBrainDecision(brainOutput) {
  const o = brainOutput || {};
  return {
    status: o.status || o.error || 'UNKNOWN',
    available: o.available === true,
    cluster_id: o.cluster?.id || o.details?.requestedZone || null,
    cluster_country: o.cluster?.country || null,
    assigned_slot: o.slot ? `${o.slot.startTime}-${o.slot.endTime}` : null,
    travel_buffer_applied: o.calendar?.travelBufferApplied || null,
    reason: o.status === 'ANCHOR_BOOKING' ? 'empty_day_anchor'
          : o.status === 'SLOT_ADJUSTED' ? 'conflict_shifted'
          : o.status === 'SLOT_AVAILABLE' ? 'slot_free'
          : o.error === 'ZONE_INCOMPATIBLE' ? (o.details?.reason || 'distance_too_far')
          : o.error === 'DAY_FULL' ? 'exceeds_work_end'
          : 'unknown'
  };
}

function buildInputSummary(nodeName, nodeOutput, body) {
  if (nodeName === 'Normalize Payload - HU') {
    return { date: body.date, duration_minutes: body.totalDuration,
             requested_slot_start: body.slotStartTime,
             city: body.locationData?.city || null,
             has_items: body.validation?.hasItems ?? null };
  }
  if (nodeName === 'Check Day Schedule' || nodeName === 'Fresh Calendar Check') {
    const events = Array.isArray(nodeOutput) ? nodeOutput.filter(e => e && e.id) : [];
    return { existing_events_count: events.length, date: body.date };
  }
  if (nodeName === 'The Brain (Logic)') {
    return { date: body.date, duration_minutes: body.totalDuration,
             requested_slot_start: body.slotStartTime };
  }
  if (nodeName === 'Slot Still Free?' || nodeName === 'Create Booking') {
    return { date: body.date };
  }
  return {};
}

function buildDecisionSummary(brain, finalStatus) {
  if (finalStatus === 'SLOT_TAKEN_ON_RECHECK') {
    return `Brain javasolt slotot (${brain.assigned_slot}), de a friss ellenorzes konfliktust talalt - foglalas elmaradt`;
  }
  if (brain.available) return `Zone ${brain.cluster_id}, slot ${brain.assigned_slot}, status ${brain.status}`;
  return `Elutasitva: ${brain.status}, ok: ${brain.reason}, zona: ${brain.cluster_id || 'ismeretlen'}`;
}

function readPrevWorkflowHash() {
  // FONTOS (v0.2.2): a lancolasi hash chainHash-szemantikaval keszul - az
  // anchor_ref-et (es a redactable-t) LEVAGJUK hash-eles elott. A sidecar
  // ugyanis utolag anchor_ref-et ir vissza a lemezen levo receiptekbe; ha a
  // teljes sort hash-elnenk, az elso horgonyzas UTANI foglalas torott
  // lancszemet irna a logba (a verifier chainHash-e anchor_ref nelkul szamol).
  try {
    if (!fs.existsSync(LOG_PATH)) return null;
    const lines = fs.readFileSync(LOG_PATH, 'utf8').trim().split('\n').filter(Boolean);
    for (let i = lines.length - 1; i >= 0; i--) {
      const rec = JSON.parse(lines[i]);
      if (rec.receipt_type === 'workflow') {
        const { anchor_ref, redactable, ...chainable } = rec;
        return sha256(chainable);
      }
    }
    return null;
  } catch (e) {
    return null;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// STEP_NODES - a tanusitando node-ok fix sorrendben.
// A logic_version es logic_hash ertekeket az axr-workflow-lint.js tartja
// szinkronban a tenyleges node-koddal:
//   node axr-workflow-lint.js workflow.json        -> drift eseten exit 1
//   node axr-workflow-lint.js workflow.json --manifest m.json -> friss hash-ek
// NE frissitsd kezzel hash-szamolas nelkul - a lint a forras.
// ═══════════════════════════════════════════════════════════════════════════════
const STEP_NODES = [
  { node: 'Normalize Payload - HU', readFrom: 'Normalize Payload - HU',
    type: 'n8n-nodes-base.code',          logic_version: '3.3 HU',
    logic_hash: 'sha256:ca343b08b7aee19b0481a1fc8609fac506051a9e40953a55e9868a026ab71563' },
  { node: 'Check Day Schedule',     readFrom: 'AXR Mark: Check Day Schedule',
    type: 'n8n-nodes-base.googleCalendar', logic_version: null, logic_hash: null },
  { node: 'The Brain (Logic)',      readFrom: 'The Brain (Logic)',
    type: 'n8n-nodes-base.code',          logic_version: '5.2 HU',
    logic_hash: 'sha256:bd4e8c1a704a052b317e27dc89f0f733bbcddf9216b8bca5b38c62ac35f44685' },
  { node: 'Fresh Calendar Check',   readFrom: 'AXR Mark: Fresh Calendar Check',
    type: 'n8n-nodes-base.googleCalendar', logic_version: null, logic_hash: null },
  { node: 'Slot Still Free?',       readFrom: 'Slot Still Free?',
    type: 'n8n-nodes-base.code',          logic_version: '2.0 HU',
    logic_hash: 'sha256:76b1266865e855c45987ca4018b4be1431ec26451ef33470e8f2316de2d1c026' },
  { node: 'Create Booking',         readFrom: 'AXR Mark: Create Booking',
    type: 'n8n-nodes-base.googleCalendar', logic_version: null, logic_hash: null }
];

// ═══════════════════════════════════════════════════════════════════════════════
// FO LOGIKA - fail-open burokban
// ═══════════════════════════════════════════════════════════════════════════════
// A passthrough MINDIG megtortenik. Ha az AXR-blokk elbukik, a __axr.error
// hordozza a hibat (lathato lyuk), de a foglalasi valasz nem serul.

const passthrough = $input.all();
let axrSummary;

try {
  const privateKeyPem = fs.readFileSync(KEY_PATH, 'utf8');
  let pepper = null;
  const warnings = [];
  try {
    pepper = loadOrCreatePepper();
  } catch (e) {
    warnings.push(`pepper nem olvashato/irhato (${e.message}) - customer_ref null`);
  }

  const nowIso = new Date().toISOString();

  const normalizeRaw = safeGet('Normalize Payload - HU');
  const normalizeClean = normalizeRaw ? splitAxrInput(normalizeRaw).output : null;
  const normalizedBody = normalizeClean && normalizeClean[0]
    ? (normalizeClean[0].body || normalizeClean[0])
    : {};
  const rawWebhookBody = normalizeClean && normalizeClean[0] && normalizeClean[0].originalPayload
    ? normalizeClean[0].originalPayload
    : normalizedBody;

  const brainRaw = safeGet('The Brain (Logic)');
  const brainClean = brainRaw ? splitAxrInput(brainRaw).output : null;
  const brainOutput = brainClean && brainClean[0] ? brainClean[0] : {};
  const brain = extractBrainDecision(brainOutput);

  const workflowReceiptId = crypto.randomUUID();

  // ── Lepes-receiptek ──────────────────────────────────────────────────────────
  const stepReceipts = [];
  let prevStepHash = null;
  let sequence = 0;

  for (const def of STEP_NODES) {
    const ran = safeGet(def.node);
    if (ran === null) continue;

    const rawOutput = safeGet(def.readFrom);
    const { input: stepInput, output: cleanOutput } =
      rawOutput === null ? { input: undefined, output: ran } : splitAxrInput(rawOutput);

    let inputHash;
    if (stepInput === undefined) {
      inputHash = null;
      warnings.push(`${def.node}: nincs __axr_input marker (readFrom: ${def.readFrom}) - input_hash null`);
    } else {
      inputHash = sha256(stepInput);
    }

    sequence += 1;
    const stepBody = {
      axr_version: AXR_VERSION,
      receipt_type: 'step',
      receipt_id: crypto.randomUUID(),
      workflow_receipt_id: workflowReceiptId,
      sequence: sequence,
      timestamp: nowIso,
      step: {
        node_name: def.node,
        node_type: def.type,
        logic_version: def.logic_version,
        logic_hash: def.logic_hash,
        model: null,
        deterministic: true
      },
      io: {
        input_hash: inputHash,
        output_hash: sha256(cleanOutput),
        input_summary: buildInputSummary(def.node, cleanOutput, normalizedBody),
        decision: def.node === 'The Brain (Logic)' ? brain : null
      },
      approval: null,
      previous_receipt_hash: prevStepHash
    };
    const signature = signReceipt(stepBody, privateKeyPem);
    const stepReceipt = { ...stepBody, signature };
    prevStepHash = sha256(stepReceipt);
    stepReceipts.push(stepReceipt);
  }

  // ── final_status ─────────────────────────────────────────────────────────────
  let finalStatus = brain.status;
  const createBookingRan = safeGet('Create Booking') !== null;
  const slotStillFreeRan = safeGet('Slot Still Free?') !== null;
  if (brain.available && slotStillFreeRan && !createBookingRan) {
    finalStatus = 'SLOT_TAKEN_ON_RECHECK';
  }

  // ── Workflow receipt ─────────────────────────────────────────────────────────
  const workflowBody = {
    axr_version: AXR_VERSION,
    receipt_type: 'workflow',
    receipt_id: workflowReceiptId,
    workflow: {
      workflow_id: 'eco-clean-geo-cluster-booking-hu',
      workflow_version: '5.1',
      webhook_path: 'booking-request-hu',
      trigger_timestamp: nowIso,
      completion_timestamp: nowIso
    },
    actor: {
      agent_id: 'eco-clean-booking-hu',
      agent_type: 'n8n-workflow',
      operator: 'Conen Digital',
      on_behalf_of: 'ECO Clean HU'
    },
    request: {
      input_hash: sha256(rawWebhookBody),
      customer_ref: customerRef(pepper, rawWebhookBody.name, rawWebhookBody.email, rawWebhookBody.phone)
    },
    outcome: {
      final_status: finalStatus,
      available: brain.available && finalStatus === brain.status,
      decision_summary: buildDecisionSummary(brain, finalStatus)
    },
    step_chain: stepReceipts.map(r => r.receipt_id),
    chain_root_hash: prevStepHash,
    approval: null,
    previous_receipt_hash: readPrevWorkflowHash()
  };
  const workflowSignature = signReceipt(workflowBody, privateKeyPem);
  const workflowReceipt = { ...workflowBody, signature: workflowSignature };

  const linesToAppend = [
    ...stepReceipts.map(r => JSON.stringify(r)),
    JSON.stringify(workflowReceipt)
  ].join('\n') + '\n';

  fs.appendFileSync(LOG_PATH, linesToAppend, 'utf8');

  axrSummary = {
    workflow_receipt_id: workflowReceiptId,
    final_status: finalStatus,
    step_count: stepReceipts.length,
    axr_version: AXR_VERSION,
    warnings: warnings,
    logged_at: nowIso
  };
} catch (e) {
  // FAIL-OPEN: a foglalas valaszol tovabb, a hiba hangos es lathato.
  axrSummary = {
    workflow_receipt_id: null,
    final_status: null,
    step_count: 0,
    axr_version: AXR_VERSION,
    error: `AXR receipt generalas elbukott: ${e.message}`,
    warnings: [],
    logged_at: new Date().toISOString()
  };
}

return passthrough.map(item => ({
  json: { ...item.json, __axr: axrSummary }
}));