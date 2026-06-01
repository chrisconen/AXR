// ═══════════════════════════════════════════════════════════════════════════════
// AXR Receipt Generator - N8N Code Node v0.2
// ═══════════════════════════════════════════════════════════════════════════════
// Beillesztes: a workflow vegere, a Respond node-ok ELE.
// Olvassa: Normalize Payload - HU, Check Day Schedule, The Brain (Logic),
//          Fresh Calendar Check, Slot Still Free?, Create Booking
// Ir: /home/node/.n8n/axr/receipts-hu.jsonl  (append-only)
// Alair: /home/node/.n8n/axr/signing-key.pem  (ed25519)
// Fuggoseg: csak beepitett modulok (crypto, fs) - NODE_FUNCTION_ALLOW_BUILTIN fedi
//
// ───────────────────────────────────────────────────────────────────────────────
// 0.2 VALTOZAS (spec 7.1): az input_hash mostantol minden lepesnel a lepes
// TENYLEGES inputjabol szamol, nem a kozos normalizalt payload-bol.
//
// EHHEZ A WORKFLOW NODE-OKAT IS MODOSITANI KELL. Minden tanusitando node a
// kimenetebe tesz egy __axr_input mezot, ami a node tenyleges bemenete:
//
//   A HAROM CODE NODE (Normalize Payload - HU, The Brain (Logic),
//   Slot Still Free?) - a return ELE:
//       const __axrInput = $input.all().map(i => i.json);
//       // ... a node sajat logikaja valtozatlanul ...
//       // a return-nel minden kimeneti itemhez:
//       return result.map(item => ({ json: { ...item.json, __axr_input: __axrInput } }));
//   (eleg az ELSO kimeneti itembe tenni; a generator onnan olvassa)
//
//   A HAROM GOOGLE CALENDAR NODE (Check Day Schedule, Fresh Calendar Check,
//   Create Booking) - sajat kodot nem futtatnak, ezert KOZVETLENUL UTANUK egy
//   mini Code node "AXR Mark: <CalendarNodeName>" nevvel, ez a tartalma:
//       const calIn  = $('<az ELOTTE levo node neve>').all().map(i => i.json);
//       const calOut = $input.all().map(i => i.json);
//       return calOut.map((item, idx) => ({
//         json: idx === 0 ? { ...item.json, __axr_input: calIn } : item.json
//       }));
//   FONTOS: a generator a Calendar node helyett a "AXR Mark: ..." node-ot
//   olvassa - lasd a STEP_NODES.readFrom mezot lent.
// ───────────────────────────────────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const fs = require('fs');

const AXR_VERSION = '0.2';
const AXR_INPUT_KEY = '__axr_input';

const AXR_DIR = '/home/node/.n8n/axr';
const LOG_PATH = AXR_DIR + '/receipts-hu.jsonl';
const KEY_PATH = AXR_DIR + '/signing-key.pem';

// ── Kanonikus szerializalas: a hash/alairas csak fix kulcssorrenddel reprodukalhato
function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}';
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
function customerRef(name, email, phone) {
  return sha256([name || '', email || '', phone || ''].join('|').toLowerCase());
}

// ── __axr_input marker levalasztasa a node kimenetterol ───────────────────────
// Visszaad: { input, output }
//   input  : a node tenyleges bemenete (a marker erteke), vagy undefined
//   output : a kimenet a marker NELKUL - ezt hash-eljuk output_hash-kent, hogy
//            a marker jelenlete ne valtoztassa meg az output_hash-t
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

// ── Biztonsagos node-kimenet olvasas: ha a node nem futott, null-t ad vissza ───
function safeGet(nodeName) {
  try {
    const items = $(nodeName).all();
    if (!items || items.length === 0) return null;
    return items.map(i => i.json);
  } catch (e) {
    return null; // a node nem futott le ebben a vegrehajtasban
  }
}

// ── Brain dontes kiemelese strukturalt formaban ────────────────────────────────
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

// ── Elozo workflow receipt hash kiolvasasa a JSONL utolso workflow sorabol ─────
function readPrevWorkflowHash() {
  try {
    if (!fs.existsSync(LOG_PATH)) return null;
    const lines = fs.readFileSync(LOG_PATH, 'utf8').trim().split('\n').filter(Boolean);
    for (let i = lines.length - 1; i >= 0; i--) {
      const rec = JSON.parse(lines[i]);
      if (rec.receipt_type === 'workflow') return sha256(rec);
    }
    return null;
  } catch (e) {
    return null;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// FO LOGIKA
// ═══════════════════════════════════════════════════════════════════════════════

// STEP_NODES - a tanusitando node-ok fix sorrendben.
//  node     : a tanusitando node logikai neve (ez kerul a receiptbe)
//  readFrom : melyik node KIMENETET olvassa a generator. A Code node-oknal ez
//             megegyezik a node-dal (sajat maguk teszik be a markert). A
//             Calendar node-oknal ez a kozvetlenul utanuk levo "AXR Mark: ..."
//             mini Code node, mert a Calendar node maga nem tud markert tenni.
const STEP_NODES = [
  { node: 'Normalize Payload - HU', readFrom: 'Normalize Payload - HU',
    type: 'n8n-nodes-base.code',          logic_version: '3.2 HU' },
  { node: 'Check Day Schedule',     readFrom: 'AXR Mark: Check Day Schedule',
    type: 'n8n-nodes-base.googleCalendar', logic_version: null     },
  { node: 'The Brain (Logic)',      readFrom: 'The Brain (Logic)',
    type: 'n8n-nodes-base.code',          logic_version: '5.0 HU' },
  { node: 'Fresh Calendar Check',   readFrom: 'AXR Mark: Fresh Calendar Check',
    type: 'n8n-nodes-base.googleCalendar', logic_version: null     },
  { node: 'Slot Still Free?',       readFrom: 'Slot Still Free?',
    type: 'n8n-nodes-base.code',          logic_version: null     },
  { node: 'Create Booking',         readFrom: 'AXR Mark: Create Booking',
    type: 'n8n-nodes-base.googleCalendar', logic_version: null     }
];

const privateKeyPem = fs.readFileSync(KEY_PATH, 'utf8');
const nowIso = new Date().toISOString();

// Normalize kimenet -> a .body tartalmazza a normalizalt adatot.
// FONTOS: a Normalize node 0.2-ben mar __axr_input markert is tartalmaz,
// ezert eloszor levalasztjuk azt, mielott a body-t kiolvassuk.
const normalizeRaw = safeGet('Normalize Payload - HU');
const normalizeClean = normalizeRaw ? splitAxrInput(normalizeRaw).output : null;
const normalizedBody = normalizeClean && normalizeClean[0]
  ? (normalizeClean[0].body || normalizeClean[0])
  : {};
const rawWebhookBody = normalizeClean && normalizeClean[0] && normalizeClean[0].originalPayload
  ? normalizeClean[0].originalPayload
  : normalizedBody;

// Brain kimenet (a markert itt is levalasztjuk a dontes kiolvasasa elott)
const brainRaw = safeGet('The Brain (Logic)');
const brainClean = brainRaw ? splitAxrInput(brainRaw).output : null;
const brainOutput = brainClean && brainClean[0] ? brainClean[0] : {};
const brain = extractBrainDecision(brainOutput);

const workflowReceiptId = crypto.randomUUID();

// ── Lepes-receiptek ────────────────────────────────────────────────────────────
const stepReceipts = [];
const warnings = [];
let prevStepHash = null;
let sequence = 0;

for (const def of STEP_NODES) {
  // a tanusitando node lefutott-e? (a Calendar node-oknal a node sajat
  // kimenete a megbizhato jel, nem a marker-node)
  const ran = safeGet(def.node);
  if (ran === null) continue;

  // a generator a readFrom node kimenetebol szedi az adatot (Code node-nal
  // ez maga a node, Calendar node-nal a "AXR Mark: ..." mini node)
  const rawOutput = safeGet(def.readFrom);
  const { input: stepInput, output: cleanOutput } =
    rawOutput === null ? { input: undefined, output: ran } : splitAxrInput(rawOutput);

  let inputHash;
  if (stepInput === undefined) {
    inputHash = null; // nincs marker - nem talalunk ki hamis hash-t
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

// ── final_status meghatarozasa ─────────────────────────────────────────────────
// Ha a Brain igent mondott de a Create Booking nem futott -> recheck konfliktus
let finalStatus = brain.status;
const createBookingRan = safeGet('Create Booking') !== null;
const slotStillFreeRan = safeGet('Slot Still Free?') !== null;
if (brain.available && slotStillFreeRan && !createBookingRan) {
  finalStatus = 'SLOT_TAKEN_ON_RECHECK';
}

// ── Workflow receipt ───────────────────────────────────────────────────────────
const workflowBody = {
  axr_version: AXR_VERSION,
  receipt_type: 'workflow',
  receipt_id: workflowReceiptId,
  workflow: {
    workflow_id: 'eco-clean-geo-cluster-booking-hu',
    workflow_version: '5.0',
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
    customer_ref: customerRef(rawWebhookBody.name, rawWebhookBody.email, rawWebhookBody.phone)
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

// ── Kiiras a JSONL-be: eloszor a lepesek, majd a workflow receipt ──────────────
const linesToAppend = [
  ...stepReceipts.map(r => JSON.stringify(r)),
  JSON.stringify(workflowReceipt)
].join('\n') + '\n';

fs.appendFileSync(LOG_PATH, linesToAppend, 'utf8');

// ── A node tovabbadja az eredeti adatot + egy axr osszefoglalo blokkot ────────
// Igy a Respond node-ok valtozatlanul mukodnek tovabb.
const passthrough = $input.all();
return passthrough.map(item => ({
  json: {
    ...item.json,
    __axr: {
      workflow_receipt_id: workflowReceiptId,
      final_status: finalStatus,
      step_count: stepReceipts.length,
      axr_version: AXR_VERSION,
      warnings: warnings,
      logged_at: nowIso
    }
  }
}));
