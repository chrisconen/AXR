// ═══════════════════════════════════════════════════════════════════════════════
// AXR Receipt Generator - N8N Code node logika v0.2
// ═══════════════════════════════════════════════════════════════════════════════
// Ez a fuggveny azt csinalja, amit az N8N Code node fog: a workflow vegen
// osszegyujti a releváns node-ok kimeneteit, es legyartja a teljes receipt-lancot.
// Az N8N-ben a $('Node Name').all() hivja vissza a node kimeneteket; itt ezt
// egy 'ctx' objektum szimulalja, hogy tesztelheto legyen a sandboxban.
//
// 0.2 valtozas (spec 7.1): az input_hash mostantol minden lepesnel a lepes
// TENYLEGES inputjabol szamol. Ezt minden tanusitando node a kimenetebe tett
// __axr_input markerbol kapjuk meg (axr-core: splitAxrInput). A generator igy
// nem feltetelez lineáris graph-ot es nem fugg a node-ok kozti elek sorrendjetol.
// ═══════════════════════════════════════════════════════════════════════════════

const axr = require('./axr-core');

// A hat tanusitando node, fix sorrendben. Amelyik nem futott le, az kimarad.
const STEP_NODES = [
  { node: 'Normalize Payload - HU', type: 'n8n-nodes-base.code',          deterministic: true, logic_version: '3.2 HU' },
  { node: 'Check Day Schedule',     type: 'n8n-nodes-base.googleCalendar', deterministic: true, logic_version: null     },
  { node: 'The Brain (Logic)',      type: 'n8n-nodes-base.code',          deterministic: true, logic_version: '5.0 HU' },
  { node: 'Fresh Calendar Check',   type: 'n8n-nodes-base.googleCalendar', deterministic: true, logic_version: null     },
  { node: 'Slot Still Free?',       type: 'n8n-nodes-base.code',          deterministic: true, logic_version: null     },
  { node: 'Create Booking',         type: 'n8n-nodes-base.googleCalendar', deterministic: true, logic_version: null     }
];

// A Brain kimenetebol kiemeli a strukturalt dontest a receipt szamara.
function extractBrainDecision(brainOutput) {
  const o = brainOutput;
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

// Egy node kimenetebol epit nem-PII input_summary-t.
function buildInputSummary(nodeName, nodeOutput, normalizedBody) {
  if (nodeName === 'Normalize Payload - HU') {
    const b = normalizedBody;
    return {
      date: b.date, duration_minutes: b.totalDuration,
      requested_slot_start: b.slotStartTime,
      city: b.locationData?.city || null, has_items: b.validation?.hasItems ?? null
    };
  }
  if (nodeName === 'Check Day Schedule' || nodeName === 'Fresh Calendar Check') {
    const events = Array.isArray(nodeOutput) ? nodeOutput.filter(e => e && e.id) : [];
    return { existing_events_count: events.length, date: normalizedBody.date };
  }
  if (nodeName === 'The Brain (Logic)') {
    const b = normalizedBody;
    return {
      date: b.date, duration_minutes: b.totalDuration,
      requested_slot_start: b.slotStartTime
    };
  }
  if (nodeName === 'Slot Still Free?') {
    return { date: normalizedBody.date };
  }
  if (nodeName === 'Create Booking') {
    return { date: normalizedBody.date };
  }
  return {};
}

// ── Fo generator ───────────────────────────────────────────────────────────────
// ctx.get(nodeName)        -> a node kimenete, vagy null ha nem futott
// ctx.normalizedBody       -> a Normalize Payload .body kimenete
// ctx.rawWebhookBody       -> a nyers webhook body (PII)
// ctx.brainOutput          -> a Brain kimenete
// ctx.prevWorkflowHash     -> az elozo workflow receipt hash-e ezen az agenten
// ctx.privateKeyPem        -> az alairo kulcs
function generateReceipts(ctx) {
  const workflowReceiptId = axr.uuid();
  const triggerTs = ctx.triggerTimestamp || new Date().toISOString();

  const actor = {
    agent_id: 'eco-clean-booking-hu',
    agent_type: 'n8n-workflow',
    operator: 'Conen Digital',
    on_behalf_of: 'ECO Clean HU'
  };

  // Figyelmeztetesek gyujtese: ha egy node nem hagyott __axr_input markert,
  // az input_hash null lesz - nem hazudunk uniform hash-t. A hivo (n8n-node)
  // ezt naplozhatja.
  const warnings = [];

  // 1. Lepes-receiptek epitese, csak a tenylegesen lefutott node-okra
  const stepReceipts = [];
  let prevStepHash = null;
  let sequence = 0;

  for (const def of STEP_NODES) {
    const rawOutput = ctx.get(def.node);
    if (rawOutput === null || rawOutput === undefined) continue; // nem futott le -> kimarad

    sequence += 1;

    // 0.2: a node kimenetebol levalasztjuk a __axr_input markert.
    //  - stepInput  : a node TENYLEGES bemenete -> ebbol szamol az input_hash
    //  - cleanOutput: a kimenet a marker NELKUL -> ebbol szamol az output_hash
    const { input: stepInput, output: cleanOutput } = axr.splitAxrInput(rawOutput);

    let inputHash;
    if (stepInput === undefined) {
      // a node nem hagyott markert - nem talalunk ki hamis hash-t
      inputHash = null;
      warnings.push(`${def.node}: nincs __axr_input marker a kimeneten - input_hash null`);
    } else {
      inputHash = axr.sha256(stepInput);
    }

    const inputSummary = buildInputSummary(def.node, cleanOutput, ctx.normalizedBody);

    const stepBody = {
      axr_version: axr.AXR_VERSION,
      receipt_type: 'step',
      receipt_id: axr.uuid(),
      workflow_receipt_id: workflowReceiptId,
      sequence: sequence,
      timestamp: ctx.stepTimestamp ? ctx.stepTimestamp(def.node) : triggerTs,
      step: {
        node_name: def.node,
        node_type: def.type,
        logic_version: def.logic_version,
        model: null,
        deterministic: def.deterministic
      },
      io: {
        input_hash: inputHash,
        output_hash: axr.sha256(cleanOutput),
        input_summary: inputSummary,
        decision: def.node === 'The Brain (Logic)'
          ? extractBrainDecision(ctx.brainOutput)
          : null
      },
      approval: null,
      previous_receipt_hash: prevStepHash
    };

    const signature = axr.signReceipt(stepBody, ctx.privateKeyPem);
    const stepReceipt = { ...stepBody, signature };
    prevStepHash = axr.sha256(stepReceipt);
    stepReceipts.push(stepReceipt);
  }

  // 2. Workflow-szintu receipt
  const brain = extractBrainDecision(ctx.brainOutput);
  const finalStatus = ctx.finalStatusOverride || brain.status;

  const workflowBody = {
    axr_version: axr.AXR_VERSION,
    receipt_type: 'workflow',
    receipt_id: workflowReceiptId,
    workflow: {
      workflow_id: 'eco-clean-geo-cluster-booking-hu',
      workflow_version: '5.0',
      webhook_path: 'booking-request-hu',
      trigger_timestamp: triggerTs,
      completion_timestamp: ctx.completionTimestamp || new Date().toISOString()
    },
    actor: actor,
    request: {
      input_hash: axr.sha256(ctx.rawWebhookBody),
      customer_ref: axr.customerRef(
        ctx.rawWebhookBody.name, ctx.rawWebhookBody.email, ctx.rawWebhookBody.phone
      )
    },
    outcome: {
      final_status: finalStatus,
      available: brain.available && finalStatus === brain.status,
      decision_summary: buildDecisionSummary(brain, finalStatus)
    },
    step_chain: stepReceipts.map(r => r.receipt_id),
    chain_root_hash: prevStepHash,
    approval: null,
    previous_receipt_hash: ctx.prevWorkflowHash || null
  };

  const workflowSignature = axr.signReceipt(workflowBody, ctx.privateKeyPem);
  const workflowReceipt = { ...workflowBody, signature: workflowSignature };
  const workflowReceiptHash = axr.sha256(workflowReceipt);

  return { workflowReceipt, workflowReceiptHash, stepReceipts, warnings };
}

function buildDecisionSummary(brain, finalStatus) {
  if (finalStatus === 'SLOT_TAKEN_ON_RECHECK') {
    return `Brain javasolt slotot (${brain.assigned_slot}), de a friss ellenorzes konfliktust talalt - foglalas elmaradt`;
  }
  if (brain.available) {
    return `Zone ${brain.cluster_id}, slot ${brain.assigned_slot}, status ${brain.status}`;
  }
  return `Elutasitva: ${brain.status}, ok: ${brain.reason}, zona: ${brain.cluster_id || 'ismeretlen'}`;
}

module.exports = { generateReceipts, STEP_NODES };
